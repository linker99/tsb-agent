动态度量审计数据库 sqlite3 audit_dm.db
打开数据库audit_dm.db 数据库中仅有audit 一个表
1.查询audit所有数据
	SELECT * FROM audit;
	eg：
		4800|1732871055|TPCM|syscall_table|DF0FB55C007BA851DCBC7F1CDFB66351EFE34A947E611078A25077A0A73BF032|1|1|0
		4801|1732871656|TPCM|syscall_table|DF0FB55C007BA851DCBC7F1CDFB66351EFE34A947E611078A25077A0A73BF032|1|1|0
		4802|1732872257|TPCM|syscall_table|DF0FB55C007BA851DCBC7F1CDFB66351EFE34A947E611078A25077A0A73BF032|1|1|0

2.查询audit结构
	PRAGMA table_info(audit);
	eg:sqlite> PRAGMA table_info(audit);
			0|id|INTEGER|0||1			//id
			1|time|INTEGER|0||0			//时间戳
			2|subject|TEXT|0||0			//主体
			3|object|TEXT|0||0			//客体
			4|hash|TEXT|0||0			//hash
			5|type|INTEGER|0||0			//度量类型
			6|result|INTEGER|0||0		//度量结果 1 成功， 2 失败
			7|count|INTEGER|0||0		//相同审计重复计数
3.根据audit表结构列名筛选查询(根据所需场景替换下命令中查询条件、查询键值即可)
	精确查询
		SELECT * FROM audit WHERE object = 'syscall_table';														//查找object列为syscall_table所有数据
		SELECT * FROM audit WHERE id = 4444;																	//查找id为4444的数据
		SELECT * FROM audit WHERE time = 1732770933;															//查找时间戳为1732770933的所有数据
		SELECT * FROM audit WHERE hash = 'DF0FB55C007BA851DCBC7F1CDFB66351EFE34A947E611078A25077A0A73BF032';	//查找hash列为...的所有数据
	模糊查询
		SELECT * FROM audit WHERE object LIKE '%kernel%';									//查询object列中包含 “kernel” 字符串的所有记录
		SELECT * FROM audit WHERE object LIKE '%table';										//查询object列中所有以table结尾的记录
		SELECT * FROM audit WHERE hash LIKE 'DF0FB55C007BA%';								//查询hash列中所有以DF0FB55C007BA开头的记录

白名单审计数据库sqlite3 audit_sm.db
打开数据库audit_sm.db 数据库中仅有audit 一个表
1.查询audit所有数据
	SELECT * FROM audit;
	eg：
		44|1731143523|root|91277|/usr/bin/bash|/root/test/sp2/exp_policy|CA64D9DB3FBE2065A9C3A06D055D8EAA6306E51B4276253EC2B186C38EBF7B61|1|2|0
		45|1731143742|root|91383|/usr/bin/bash|/root/test/1.sh|C6FCEE46C8639AAC1C18AD6ADE1F4B8F99EE04A0DD5FF3272CFCC0B3E565F3DE|1|2|0
		46|1731143760|root|91387|/usr/bin/bash|/root/test/sp2/exp_policy|CA64D9DB3FBE2065A9C3A06D055D8EAA6306E51B4276253EC2B186C38EBF7B61|1|2|0
2.查询audit结构
	PRAGMA table_info(audit);
	eg:sqlite> PRAGMA table_info(audit);
			0|id|INTEGER|0||1			//id
			1|time|INTEGER|0||0			//时间戳
			2|user|TEXT|0||0			//用户
			3|pid|INTEGER|0||0			//pid
			4|subject|TEXT|0||0			//主体
			5|object|TEXT|0||0			//客体
			6|hash|TEXT|0||0			//hash
			7|operate|INTEGER|0||0		//操作(执行)
			8|result|INTEGER|0||0		//度量结果(成功\失败\学习) 1 成功， 2 失败
			9|count|INTEGER|0||0		//相同审计重复计数
3.根据audit表结构列名筛选查询(根据所需场景替换下命令中查询条件、查询键值即可)
	精确查询
		SELECT * FROM audit WHERE object = '/root/test/1.sh';													//查找object列为/root/test/1.sh的数据
		SELECT * FROM audit WHERE id = 60;																		//查找id为60的数据
		SELECT * FROM audit WHERE time = 1732770933;															//查找时间戳为1732770933的所有数据
		SELECT * FROM audit WHERE hash = '8BC4E397CC1270C82596AFBB150ACFA262EA141ADF3B18AF68C7D76751F47A81';	//查找hash列为...的所有数据
	模糊查询
		SELECT * FROM audit WHERE object LIKE '%test%';									//查询object列中包含 “test” 字符串的所有记录
		SELECT * FROM audit WHERE object LIKE '%.sh';									//查询object列中所有以.sh结尾的记录
		SELECT * FROM audit WHERE hash LIKE 'DF0FB55C007BA%';							//查询hash列中所有以DF0FB55C007BA开头的记录

白名单数据库sqlite3 whitelist.db
1.查询whitelist所有数据
	SELECT * FROM whitelist;
	eg：
		47d0ce5a-d534-44e8-ab64-e6373417cd9c|/root/test/srv.bak|0FE875A24CCB916C8BDC6F1409D243DEAA75CBFD098F770A27CF9102D9F5F498|3
		5cc6b075-0f11-4670-8271-ec9dce078262|/root/test/srv|6A96FD2BCB71DA16C5CFBA3749A581D8B238D5617765B85C27D1FACA4ABB149C|3
		85e1249c-20f5-4b8d-84f7-6ad5cb8f7210|/root/test/srv.bak|6A96FD2BCB71DA16C5CFBA3749A581D8B238D5617765B85C27D1FACA4ABB149C|3
2.查询whitelist结构
	PRAGMA table_info(whitelist);
	eg:sqlite>PRAGMA table_info(whitelist);
			0|guid|text|0||0			//guid
			1|path|text|0||0			//路径
			2|hash|text|0||0			//hash
			3|source|int|0||0			//来源  3：本地配置 2：管理中心配置 1：初始采集
3.根据whitelist表结构列名筛选查询(根据所需场景替换下命令中查询条件、查询键值即可)
	精确查询
		SELECT * FROM whitelist WHERE path = '/root/test/srv';														//查找path列为/root/test/srv的数据
		SELECT * FROM whitelist WHERE source = 3;																	//查找来源为本地配置的数据
		SELECT * FROM whitelist WHERE hash = '8BC4E397CC1270C82596AFBB150ACFA262EA141ADF3B18AF68C7D76751F47A81';	//查找hash列为...的所有数据
	模糊查询
		SELECT * FROM whitelist WHERE path LIKE '%test%';									//查询path列中包含 “test” 字符串的所有记录
		SELECT * FROM whitelist WHERE path LIKE '%.sh';										//查询path列中所有以.sh结尾的记录
		SELECT * FROM whitelist WHERE hash LIKE 'DF0FB55C007BA%';							//查询hash列中所有以DF0FB55C007BA开头的记录

