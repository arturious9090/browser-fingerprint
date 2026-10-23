// Fixed event names and server-generated identifiers only. Never log request
// headers, bodies, URLs, IPs, owner keys, CSRF values or session tokens.
const events=new Set(['login_success','login_denied','logout','session_denied','csrf_denied','origin_denied','rate_limited','quota_reached','reports_read','report_read','request_failed']);
export function createAuditLogger({sink=line=>console.info(line),now=Date.now,perMinute=10}={}){
  const buckets=new Map();
  return (event,requestId,status)=>{
    if(!events.has(event)||!Number.isInteger(status)||status<100||status>599||!/^[a-f0-9]{16}$/.test(requestId))return;
    const time=now();let bucket=buckets.get(event),suppressed=0;
    if(!bucket||bucket.until<=time){suppressed=bucket?.suppressed??0;bucket={until:time+60000,count:0,suppressed:0};buckets.set(event,bucket);}
    if(bucket.count++>=perMinute){bucket.suppressed++;return;}
    try{sink(JSON.stringify({time:new Date(time).toISOString(),event,requestId,status,...(suppressed?{suppressed}:{} )}));}catch{/* A failed log sink must not change authorization or crash requests. */}
  };
}
