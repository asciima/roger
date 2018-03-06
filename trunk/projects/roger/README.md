# roger

build 

          for windows  
            server: projects/roger/projects/msvc/roger/rserver.sln    
            client: projects/roger/projects/msvc/roger_client/roger.sln  
            please note that if you want to debug cilent in MS IDE, you must set debug parameter first 
            (ip and port in command arguments)
          
          for linux  
            makefile path: projects/roger/projects/linux/makefile
            make example: make build=debug arch=x86_64 udns wawo roger_server
            make example: make build=debug arch=x86_64 udns wawo roger_client
            make example: make roger_server
            make example: make roger_client
			make example：make udns_clean wawo_clean roger_server_clean
			make example: make udns_clean wawo_clean roger_client_clean
            
            binary file would be in: projects/roger/projects/build/$(ARCH)
            
            codeblock project file:  
            server: projects/roger/projects/codeblocks/roger/roger.workspace
            
		  for raspberry pi
			make build=debug arch=armv7 udns wawo roger_client 
			make build=release arch=armv7 roger_client
			make build=debug arch=armv7 udns_clean wawo_clean
			
usage

          1, start server
          	./roger_server 0.0.0.0 12120 > /dev/null &
          
          2, start client
          	roger_client roger_server_ip 12120
          
          3, setup proxy on browser side   
          	pac address: http://roger_client_ip:8088/proxy.pac   
          	socks5,socks4,http,https: roger_client_ip 12122  

discussion group: QQ(452583496)



This is a protocol test project based upon wawo library, we are opposed to any violence and illegal usage or spread, thanks. 



