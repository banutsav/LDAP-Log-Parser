/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package LDAP_log_monitor;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Properties;
import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 *
 * @author utsavb
 */
public class email {
    
    public static void sendEmailReport(String job_time) throws UnsupportedEncodingException, AddressException, MessagingException
    { 
        final Properties smtpSettings = new Properties();
        smtpSettings.setProperty("mail.smtp.host", "mail.ovpr.uga.edu");
        smtpSettings.setProperty("mail.smtp.from", "noreply@ovpr.uga.edu");
        
        final Session session = Session.getInstance(smtpSettings, null);
        final MimeMessage message = new MimeMessage(session);
        
        final ArrayList<Address> toRecipientsAddrs = new ArrayList();
        
        // get email addresses
        String[] elements = Main.poc_emails.split(";");
        
        for(String s: elements)
        {    
           toRecipientsAddrs.add(new InternetAddress(s));
        }
            
        
        message.addRecipients(Message.RecipientType.TO, toRecipientsAddrs.toArray(new Address[0]));
        
        
        message.setSubject("OVPR-UGA: LDAP Processing Cron Job Notification");
        
        
        String msgBody = "LDAP Log monitor for Logs dated: " + Main.log_file_date + "<br><br>" +
                "Total connections = " + Main.total + "<br>" +
                //"Total success = " + Main.pass + "<br>" +
                //"Total failures = " + Main.fail + "<br>" +
                "Retries = " + Main.fail_retry + "<br>" +
                //"Connection Lost = " + Main.fail_conn_lost + "<br>" +
                "Error code 32 = " + Main.fail_32 + "<br>" +
                "Error code 49 = " + Main.fail_49 + "<br><br>" +
                job_time + "<br><br>" +
                "Output file location = <b>" + Main.incoming_file_path + "</b><br>"
                ;
                
        message.setContent(msgBody,"text/html");
        
        //System.out.println(msgBody);
        
        
        Transport.send(message); 
        
        System.out.println("LDAP log email report sent");
        
    }
    
}
