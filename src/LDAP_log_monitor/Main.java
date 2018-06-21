/* 
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package LDAP_log_monitor;

import LDAP_log_monitor.email;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.Properties;
import org.apache.commons.lang.StringEscapeUtils;

/**
 *
 * @author utsavb
 */
public class Main {

    public static String file_path;
    public static String incoming_file_path;
    public static String timestamp, ip, conn_number, userid;
    public static String err_code;
    public static String retry_url;
    public static String conn_lost;
    public static String information;
    public static String ldap_response;
    public static Date conn_timestamp;
    public static Date conn_end_timestamp;

    public static String poc_emails;

    public static String mysqlAddress;
    public static String mysqlUsername;
    public static String mysqlPassword;
    public static String mysqlSchema;

    public static String log_file_date;
    public static int total = 0, pass = 0, fail = 0, fail_retry = 0, fail_conn_lost = 0;
    public static int fail_32 = 0, fail_49 = 0;

    public static final int max_record_size = 7000;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {

        final long startTime = Calendar.getInstance().getTimeInMillis();
        System.out.println("");
        System.out.println("=====================");
        System.out.println("LDAP log monitor job");
        System.out.println("=====================");
        System.out.println(Calendar.getInstance().getTime().toString());
        System.out.println("");

        /*
         see if any command line parameters
         if so, set them to the respective file paths
         */
        loadProperties();
        setOutputFileName();

        if (args.length == 2) {
            file_path = args[0];
            incoming_file_path = args[1];
        }

        readFile();

        //removeLegacyData(); // NOT IMPLEMENTED, NEEDS MORE WORK
        final long endTime = Calendar.getInstance().getTimeInMillis();
        final long elapsedTime = endTime - startTime;

        // send email report
        //email.sendEmailReport("The LDAP Log processing job ran for: " + (elapsedTime / 60000) + "m " + (elapsedTime % 60000 / 1000) + "s");
        System.out.println("Total elapsed time: " + (elapsedTime / 60000) + "m " + (elapsedTime % 60000 / 1000) + "s");

        System.out.println("Program completed.");

    }

    // remove old stale data 
    public static void removeLegacyData() throws Exception {
        System.out.println("\nRemoving legacy login data from database...");
        Class.forName("com.mysql.jdbc.Driver").newInstance();
        Connection conn = null;
        Statement stmt = null, stmt1 = null;
        int count = 0;

        try {
            conn = DriverManager.getConnection(Main.mysqlAddress, Main.mysqlUsername, Main.mysqlPassword);
            stmt = conn.createStatement();
            stmt1 = conn.createStatement();

            stmt1.execute("START TRANSACTION;");

            final String query = "select `user_id`, `connection_num` from `" + Main.mysqlSchema + "`.`remove_old_login_data`";
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                String user = rs.getString("user_id");
                String conn_num = rs.getString("connection_num");
                final String delete1 = "delete from `LDAP_logs`.`conn_details` where `user_id`='" + user + "' and `connection_num`='" + conn_num + "'";
                final String delete2 = "delete from `LDAP_logs`.`login_details` where `user_id`='" + user + "' and `connection_num`='" + conn_num + "'";

                stmt1.executeUpdate(delete1);
                stmt1.executeUpdate(delete2);
                //System.out.println("removed user = " + user + ", conn = " + conn_num);
                count++;
            }

            System.out.println("Total stale records removed = " + count);
            rs.close();
            stmt1.execute("COMMIT;");
        } catch (Exception e) {
            stmt1.execute("ROLLBACK;");
            e.printStackTrace();
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (Exception ex) {
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (Exception ex) {
                }
            }
        }
    }

    // output file should have the date of the dump
    public static void setOutputFileName() throws FileNotFoundException, IOException {
        BufferedReader reader = new BufferedReader(new FileReader(file_path));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] elements = line.split("\\s+");
            incoming_file_path += "-" + elements[0] + "-" + elements[1] + ".txt";
            //System.out.println(incoming_file_path);
            log_file_date = elements[0] + "-" + elements[1];
            break;
        }

        reader.close();
    }

    public static void readFile() throws FileNotFoundException {
        System.out.println("Reading the LDAP syslog data dump...");
        System.out.println("Input file = " + file_path);
        System.out.println("Output file = " + incoming_file_path);

        try {

            BufferedReader reader = new BufferedReader(new FileReader(file_path));

            File logFile = new File(incoming_file_path);
            BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));

            String line, conn_num, search;
            while ((line = reader.readLine()) != null) {
                
                if (line.contains("ACCEPT")) {
                    
                    //count total incoming connections
                    total++;

                    conn_num = processAcceptLine(line);
                    search = "conn=" + conn_num;

                    //writer.write("Connection information for connection number = " + conn_num + "\n");

                    err_code = "0";
                    retry_url = "0";
                    conn_lost = "0";
                    userid = extractConnectionDetails(search, writer);

                    //getConnectionDateTime();
                    //writeIncomingRequestDetails(); // WRITE DATA TO MYSQL
                }
            }
            reader.close();
            writer.close();
        } catch (Exception e) {
            System.err.format("Exception occurred in readFile()" + file_path);
            e.printStackTrace();
        }
    }

    // extract connection date and time
    public static void getConnectionDateTime() throws ParseException {
        // get current year, syslogs don't tell the year
        Calendar now = Calendar.getInstance();
        int year = now.get(Calendar.YEAR);
        String yearInString = String.valueOf(year);

        String[] elements = timestamp.split("\\s+");

        String date = elements[0] + " " + elements[1] + " " + yearInString + " " + elements[2];

        //System.out.println(date);
        SimpleDateFormat formatter = new SimpleDateFormat("MMM dd yyyy hh:mm:ss", Locale.US);
        Date input_date = formatter.parse(date);
        conn_timestamp = input_date;

        //System.out.println(conn_timestamp);
    }

    // process CLOSED line and get the end time
    public static String processClosedLine(String line) {
        // sample LDAP accept line
        // Feb 20 06:47:23 ldap slapd[1177]: conn=1251 fd=24 ACCEPT from IP=128.192.92.132:45375 (IP=0.0.0.0:636)
        String end_time;

        String[] elements = line.split("\\s+");

        end_time = elements[0] + " " + elements[1] + " " + elements[2];
        return end_time;
    }

    // get connection end time
    public static void getConnectionEndTime(String end_line) throws ParseException {
        // get current year, syslogs don't tell the year
        Calendar now = Calendar.getInstance();
        int year = now.get(Calendar.YEAR);
        String yearInString = String.valueOf(year);

        String[] elements = processClosedLine(end_line).split("\\s+");

        String date = elements[0] + " " + elements[1] + " " + yearInString + " " + elements[2];

        //System.out.println(date);
        SimpleDateFormat formatter = new SimpleDateFormat("MMM dd yyyy hh:mm:ss", Locale.US);
        Date input_date = formatter.parse(date);
        conn_end_timestamp = input_date;

    }

    // get the elapsed time
    public static long getElapsedTime(Timestamp start, Timestamp end) throws ParseException {
        long elapsed = 0;

        DateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date StartDate = sdf.parse(start.toString());
        Date EndDate = sdf.parse(end.toString());

        elapsed = EndDate.getTime() - StartDate.getTime();

        return (elapsed / 1000);
    }

    // write any associated errors for incoming requests to SQL database
    public static void writeIncomingRequestDetails() throws Exception {
        Class.forName("com.mysql.jdbc.Driver").newInstance();
        Connection conn = null;
        Statement stmt = null;
        try {

            conn = DriverManager.getConnection(Main.mysqlAddress, Main.mysqlUsername, Main.mysqlPassword);
            stmt = conn.createStatement();

            // determine if pass or fail
            int conn_status = 0;
            if ((err_code.equals("0")) && (retry_url.equals("0")) && (conn_lost.equals("0"))) {
                // count success
                pass++;
                conn_status = 1;
            } else {
                // count failures by error codes
                if (err_code.equals("32")) {
                    fail_32++;
                }
                if (err_code.equals("49")) {
                    fail_49++;
                }

                // count failure
                fail++;
            }

            // check if entry is already there
            final String check = "select `user_id` from `" + Main.mysqlSchema + "`.`login_details` where `connection_num` = '" + StringEscapeUtils.escapeSql(conn_number) + "'"
                    + " and `user_id` = '" + StringEscapeUtils.escapeSql(userid) + "'";

            //System.out.println(check);
            ResultSet rs = stmt.executeQuery(check);
            if (rs.next()) {
                //System.out.println("entry exists - " + conn_number + ", " + userid);
                return;
            }

            Timestamp timestamp = new Timestamp(conn_timestamp.getTime());
            Timestamp end_timestamp = new Timestamp(conn_end_timestamp.getTime());

            // check if string is beyond the max limit 
            if (information.length() > max_record_size) {
                information = "0";
            }

            //System.out.println("conn=" + conn_number + ", start time=" + timestamp + ", end time=" + end_timestamp);
            //System.out.println("elapsed time=" + getElapsedTime(timestamp, end_timestamp) + " sec");
            final String insert = "INSERT INTO `" + Main.mysqlSchema + "`.`login_details` SET "
                    + " `user_id` = '" + StringEscapeUtils.escapeSql(userid) + "'"
                    + ", `connection_num` = '" + StringEscapeUtils.escapeSql(conn_number) + "'"
                    + ", `ip_address` = '" + StringEscapeUtils.escapeSql(ip) + "'"
                    + ", `timestamp` = '" + timestamp + "'"
                    + ", `error_code` = '" + StringEscapeUtils.escapeSql(err_code) + "'"
                    + ", `retry_url` = '" + StringEscapeUtils.escapeSql(retry_url) + "'"
                    + ", `conn_lost` = '" + StringEscapeUtils.escapeSql(conn_lost) + "'"
                    + ", `server` = '" + StringEscapeUtils.escapeSql(ldap_response) + "'"
                    + ", `conn_status` = '" + conn_status + "'"
                    + ", `elapsed_time` = '" + getElapsedTime(timestamp, end_timestamp) + "'";

            //System.out.println(information);
            stmt.executeUpdate(insert);

            //insert verbose information for a connection
            Statement stmtInfo = conn.createStatement();

            final String insertInfo = "INSERT INTO `" + Main.mysqlSchema + "`.`conn_details` SET "
                    + " `user_id` = '" + StringEscapeUtils.escapeSql(userid) + "'"
                    + ", `connection_num` = '" + StringEscapeUtils.escapeSql(conn_number) + "'"
                    + ", `information` = '" + StringEscapeUtils.escapeSql(information) + "'";

            stmtInfo.executeUpdate(insertInfo);
            //System.out.println("information inserted for " + conn_number + ", " + userid);
        } catch (Exception e) {
            System.err.format("Exception occurred in method writeIncomingRequests()");
            e.printStackTrace();
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (Exception ex) {
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (Exception ex) {
                }
            }
        }
    }

    /*
     extract the data chunk for a particular incoming connection
     sample chunk - 
            
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 fd=42 ACCEPT from IP=128.192.92.132:32954 (IP=0.0.0.0:636)
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 fd=42 TLS established tls_ssf=128 ssf=128
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 op=0 BIND dn="cn=admin,dc=ovpr,dc=uga,dc=edu" method=128
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 op=0 BIND dn="cn=admin,dc=ovpr,dc=uga,dc=edu" mech=SIMPLE ssf=0
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 op=0 RESULT tag=97 err=0 text=
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 op=1 SRCH base="ou=users,dc=ovpr,dc=uga,dc=edu" scope=2 deref=3 filter="(&(cn=*)(sn=*)(ugaAuthCheck=*)(ugaCan=*))"
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 op=1 SRCH attr=cn sn ugaAuthCheck ugaCan
     Feb 17 07:00:07 ldap slapd[869]: <= bdb_equality_candidates: (objectClass) not indexed
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 op=1 SEARCH RESULT tag=101 err=0 nentries=712 text=
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 op=2 UNBIND
     Feb 17 07:00:07 ldap slapd[869]: conn=139791 fd=42 closed
    
     also, extract and return the "userid"
     */
    public static String extractConnectionDetails(String search, BufferedWriter writer) {
        //System.out.println("search for = " + search);
        String line, userid = "";
        int cn_found = 0;
        int an_bind = 0;

        // global variables set to blank
        ldap_response = "";
        information = "";
        conn_end_timestamp = null;

        try {
            BufferedReader reader = new BufferedReader(new FileReader(file_path));

            while ((line = reader.readLine()) != null) {

                if (line.contains(search)) {

                    if (line.contains("cn=") && (cn_found == 0)) {
                        String[] elements = line.split("cn=");
                        String[] elements_2 = elements[1].split(",");
                        userid = elements_2[0];
                        cn_found = 1;
                    }
                    
                    if(((userid.equals("s_02"))||(userid.equals("s_03")||(userid.equals("admin"))||(userid.equals("UMD-00009-1")))&&(cn_found==1))){
                        return userid;
                    }
                    
                    writer.write(line + "\n");

                    /*
                    
                    information += line + "\n";

                    // see if BIND is to UGA LDAP or OVPR LDAP
                    if (line.contains("BIND dn=\"\"")) {
                        an_bind = 1; // bind from OVPR LDAP
                    }
                    // extract user id, line format something resembling (but not restricted to) - 
                    //Feb 23 08:04:06 ldap slapd[1177]: conn=4233 op=1 SRCH base="cn=tefycar,ou=users,o=meta" scope=2 deref=2 filter="(cn=tefycar)"

                    // extract error code
                    if (line.contains("RESULT")) {
                        extractErrorCode(line);
                    }

                    // extract URL retries
                    if (line.contains("retrying")) {
                        fail_retry++;
                        extractURLRetries(line);
                    }
                    // check if connection lost
                    if (line.contains("connection lost")) {
                        fail_conn_lost++;
                        conn_lost = "1";
                    }

                    // get end timestamp
                    if (line.contains("closed")) {
                        getConnectionEndTime(line);
                    }

                    */
                    
                }
            }
            reader.close();

            writer.write("\n\n");

            if ((an_bind == 1) || (ip.contains("[::]:389"))) {
                ldap_response = "OVPR";
            } else {
                ldap_response = "UGA";
            }

            return userid;

        } catch (Exception e) {
            System.err.format("Exception in method extractConnectionDetails() occurred, trying to read " + file_path);
            e.printStackTrace();
        }

        return null;
    }

    /*
     extract URL retries
     */
    public static void extractURLRetries(String line) {
        //System.out.println(line);
        String[] elements = line.split("retrying");
        retry_url = elements[1];

    }

    /*
     extract error code from RESULT line
     */
    public static void extractErrorCode(String line) {
        //System.out.println(line);
        String[] elements = line.split("err=");
        String[] elements_2 = elements[1].split("\\s+");
        if (!elements_2[0].equals("0")) {
            err_code = elements_2[0];
        }
    }

    /* 
     extract connection number, timestamp, IP 
     from each incoming connection
     return the connection number
     */
    public static String processAcceptLine(String line) {
        // sample LDAP accept line
        // Feb 20 06:47:23 ldap slapd[1177]: conn=1251 fd=24 ACCEPT from IP=128.192.92.132:45375 (IP=0.0.0.0:636)
        String conn;

        String[] elements = line.split("\\s+");
        String[] elements_1 = line.split("conn=");
        String[] elements_2 = elements_1[1].split("\\s+");
        String[] elements_3 = line.split("IP=");

        timestamp = elements[0] + " " + elements[1] + " " + elements[2];
        conn = elements_2[0];
        ip = elements_3[1] + " " + elements_3[2];
        conn_number = conn;

        return conn;
    }

    //UTILITY
    private static void loadProperties() throws Exception {
        FileInputStream in = null;
        try {
            final String temp = Main.class.getProtectionDomain().getCodeSource().getLocation().toString();
            final String jarFolder = temp.substring(temp.indexOf("/"), temp.lastIndexOf("/") + 1);
            in = new FileInputStream(jarFolder + "config.properties");
            final Properties props = new Properties();
            props.load(in);
            file_path = props.getProperty("filePath");
            incoming_file_path = props.getProperty("incomingFilePath");
            mysqlAddress = props.getProperty("mysqlAddress");
            mysqlUsername = props.getProperty("mysqlUsername");
            mysqlPassword = props.getProperty("mysqlPassword");
            mysqlSchema = props.getProperty("mysqlSchema");

            poc_emails = props.getProperty("poc_emails");

        } catch (Exception ex) {
            throw ex;
        } finally {
            try {
                in.close();
            } catch (Exception ex) {
            }
        }
    }
}
