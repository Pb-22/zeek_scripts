@load base/protocols/http

module HTTP_Server;

export {
    
    type Info: record {
        uid: string &log &optional;
        server_type: string &log &default="";
        #header_name: string &log &default="";
        #header_value: string &log &default="";
        
        };

    redef enum Log::ID += { HTTP_SERVER_DETECTION };
    global log_http_server_detection: event(rec: Info);

    redef record HTTP::Info += {
        declared_server: string &log &optional;
    };
}

event zeek_init() &priority=5 {
    Log::create_stream(HTTP_Server::HTTP_SERVER_DETECTION,
        [$columns=Info, $ev=log_http_server_detection, $path="http_server_detection"]);
}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) {
    if ( !is_orig && name == "SERVER" ) {
        local rec: Info = [$uid=c$uid, $server_type=value]; 
        #These other fields can be added if needed
        #$header_name=original_name, $header_value=value];
        #Also other headers could be singled out and added for other purposes:
        #see https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
        # or https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers for more ideas 
        Log::write(HTTP_Server::HTTP_SERVER_DETECTION, rec);
        c$http$declared_server = value;
    }
}
