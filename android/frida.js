import http from 'http';
import url from "url";


Java.perform(function () {    
    const DocumentBuilderFactory = Java.use("javax.xml.parsers.DocumentBuilderFactory")
    const File = Java.use('java.io.File')
    const personalPackageId = "com.whatsapp"
    const businessPackageId = "com.whatsapp.w4b"
    const personalServerPort = 1314
    const businessServerPort = 1315

    var  currentNumber = null                

    function hook(packageName,packageVersion) {        
        var versionFound = false    

        if (packageName==personalPackageId) {

            if (packageVersion=="2.25.37.76") {
                versionFound=true        
                Java.perform(function () {
                    var Reader = Java.use('X.8y0');	
                    Reader.A06.implementation = function () {                                                  
                        var node = this.A06()                                          
                        if (node!=null) {                                                                        
                            var xml = node.toString()                                                   
                            try { send(`[XML recv] ${xml}`); } catch (_) { console.log("LOG ERROR") }
                        } else {
                            try { send(`[CONNECTION MAYBE LOST]`); } catch (_) { console.log("LOG ERROR") }
                        }
                        return node;
                    };     

                    var Writer = Java.use('X.9Kc'); 
                    var rootCall = true

                    Writer.A01.implementation = function (a,b) {                                  
                        if (rootCall) {                                                        
                            try { send(`[XML send] ${a.toString()}`); } catch (_) { console.log("LOG ERROR") }
                            rootCall = false;
                            this.A01(a,b);
                            rootCall = true;
                        } else {
                            this.A01(a,b);
                        } 
                    };                                                     
                });      
            }                         
        } else {
            if (packageVersion=="2.25.37.76") {
                versionFound=true        
                Java.perform(function () {
                    var Reader = Java.use('X.8kp');		
                    Reader.A06.implementation = function () {                             
                        var node = this.A06()                  
                        if (node!=null) {                                                                                       
                            var xml = node.toString()                                                  
                            try { send(`[XML recv] ${xml}`); } catch (_) { console.log("LOG ERROR") }
                        } else {
                            try { send(`[CONNECTION MAYBE LOST]`); } catch (_) { console.log("LOG ERROR") }
                        }
                        return node;
                    };
                    var Writer = Java.use('X.94F')
                    var rootCall = true
                    Writer.A01.implementation = function (a,b) {                                  
                        if (rootCall) {                                                        
                            try { send(`[XML send] ${a.toString()}`); } catch (_) { console.log("LOG ERROR") }
                            rootCall = false;
                            this.A01(a,b);
                            rootCall = true;
                        } else {
                            this.A01(a,b);
                        } 
                    };   

                });                    
            }                               
        }     

        if (!versionFound) {
            send("CANNOT HOOK BECAUSE THE VERSION NOT FOUND")
        }        

        return versionFound
        
    }    

    function getXmlItemValues(path,tag,keys) {               
        var file = File.$new(path)        
        if (!file.exists()) {            
            return {"error":-1,"msg":"File does not exist"}
        }        
        var documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
        var ret = {}
        var nodes = documentBuilder.parse(file).getElementsByTagName(tag)
        if (nodes.getLength()==0) {
            return ret
        }
        for (var i=0;i<nodes.getLength();i++) {
            var node = nodes.item(i)            
            var name = node.getAttributes().getNamedItem("name")
            if (name) {
                name = name.getNodeValue()
                if (keys.indexOf(name)>=0) {
                    let value = node.getTextContent()                    
                    if (value==null || value=="") {
                        value = node.getAttributes().getNamedItem("value")                        
                        if (value) {
                            value = value.getNodeValue()
                        }                        
                    }
                    ret[name] = value
                }          
            }  
        }
        return ret
    }     

    function getCurrentNumber(packageName) {        
        if (currentNumber==null) {
            let data = getXmlItemValues('/data/data/'+packageName+'/shared_prefs/'+packageName+'_preferences_light.xml',"string",["registration_jid"])            
            currentNumber = data["registration_jid"]            
            let data2 = getXmlItemValues('/data/data/'+packageName+'/shared_prefs/startup_prefs.xml',"int",["registration_device_id"])
            let deviceId = data2["registration_device_id"]            
            if (deviceId!="0") {
                currentNumber+=":"+deviceId
            }
        }        
        return currentNumber
    }


    const ActivityThread = Java.use('android.app.ActivityThread')
    let context = ActivityThread.currentApplication().getApplicationContext()        
    let packageName = context.getPackageName()    
    let packageInfo = context.getPackageManager().getPackageInfo(packageName, 0)        
    let packageVersion = packageInfo.versionName.value    
                
    send("Initializing...")            
    if (hook(packageName,packageVersion)) {
        send("HOOKED MESSAGE OK")
    }    

    const serverPort = (packageName=== personalPackageId) ? personalServerPort : businessServerPort

    const server = http.createServer((req, res) => {
        try {
            //默认全部按200返回吧            
            const method = req.method                
            let parsedRequest = url.parse(req.url, true)
            if (method === 'GET') {
                switch (parsedRequest.pathname) {
                    case "/number":
                        res.writeHead(200, {"Content-Type": "application/json"});
                        res.end(JSON.stringify({"retcode":0,"number":getCurrentNumber(packageName)}))                                                
                        return                         
                    default:
                        res.writeHead(200, {"Content-Type": "application/json"});
                        res.end(JSON.stringify({"error": "Unknown command"}))
                        return 
                }
            } else {
                res.writeHead(200, {"Content-Type": "application/json"});
                res.end(JSON.stringify({"error": "method not support"}))
                return 
            }

        } catch (error) {
            res.writeHead(200, {"Content-Type": "application/json"});
            res.end(JSON.stringify({"error": error.toString() + "\n" + error.stack}))
        }
    })
    
    server.listen(serverPort, () => {
        send("Server ready on port " +serverPort)
    })    
        
})









