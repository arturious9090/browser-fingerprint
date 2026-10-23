import http from 'node:http';
const request=http.get({socketPath:process.env.PROXY_SOCKET??'/run/fingerprint/app.sock',path:'/healthz',timeout:3000},res=>{res.resume();process.exitCode=res.statusCode===200?0:1;});
request.on('timeout',()=>request.destroy());request.on('error',()=>{process.exitCode=1;});
