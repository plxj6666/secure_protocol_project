## 握手，挥手方面的更新（1/6——16：36——by wyp）
1.增加了clien.c  server.c 用于运行时客户端和服务器端的启动（这样就不需要main.c）
2.在sig.h增加了用于握手和挥手的宏定义区分消息类别
3.在client_main.c,server_main.c,terminate_session.c中增加了四次挥手的处理