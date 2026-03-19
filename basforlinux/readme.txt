警告：
本主机安全验证测试有系统性风险，需在隔离测试环境下进行，本验证工具适用于linux平台，包含ATT&CK框架下TTPS大约 67，即有67个攻击测试用例。

使用步骤：
一、上传本工具包到/opt目录下,赋予run_all_atomics.sh、goart-linux的执行权限
1) chmod 777  run_all_atomics.sh   
2)chmod 777  goart-linux  
 
二、执行安全测试sudo sh  run_all_atomics.sh  全量测试

三、sudo sh  run_all_atomics.sh --help 获得帮助

四、测试完成后，日志在logs目录下

五、运行analyze_atomic_logs2.py 解析日志生成报告脚本，报告会自动生成到reports目录 （需要先安装python3 依赖，pip3 install -r requirements.txt)

六、analyze_atomic_logs2.py  --help获得帮助