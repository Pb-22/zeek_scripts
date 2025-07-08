# Zeek Script: HTTP Server Header Detection

## Purpose

This Zeek script logs the value of the `Server` HTTP response header observed in network traffic. By recording this information, analysts can quickly identify the types and versions of web servers responding on the network, which is useful for asset discovery, vulnerability management, and threat hunting.

The script creates a custom log stream (`http_server_detection.log`) containing the connection UID and the server type string for each HTTP response that includes a `Server` header.

---

## How the Script Works

* **Custom Log Stream:** Sets up a new log (`http_server_detection.log`) via Zeek’s logging framework.
* **Event Handler:** Listens for the `http_header` event and, for each observed `Server` header in HTTP *responses* (not requests), writes an entry to the custom log.
* **Optional Extension:** The script is structured to be easily modified for logging additional or different headers.

---

## How to Capture Other HTTP Headers

To extend this script and capture other HTTP headers (such as `Set-Cookie`, `X-Powered-By`, or custom headers):

1. **Add New Fields to the Record:**

   * Uncomment and extend the `header_name` and `header_value` fields in the `Info` record.

   ```zeek
   type Info: record {
       uid: string &log &optional;
       server_type: string &log &default="";
       header_name: string &log &default="";    # Add this
       header_value: string &log &default="";   # Add this
   };
   ```

2. **Modify the Event Handler:**

   * Update the `http_header` event to capture the desired header(s).
   * You can either log all headers or just specific ones by changing the conditional check.

   ```zeek
   event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) {
       # Example: Log multiple headers
       if ( !is_orig && ( name == "SERVER" || name == "SET-COOKIE" || name == "X-POWERED-BY" ) ) {
           local rec: Info = [$uid=c$uid, $server_type=(name == "SERVER" ? value : ""), $header_name=original_name, $header_value=value];
           Log::write(HTTP_Server::HTTP_SERVER_DETECTION, rec);
           if (name == "SERVER") {
               c$http$declared_server = value;
           }
       }
   }
   ```

   * To log **all response headers**, simply remove the header name check:

   ```zeek
   if ( !is_orig ) {
       local rec: Info = [$uid=c$uid, $header_name=original_name, $header_value=value];
       Log::write(HTTP_Server::HTTP_SERVER_DETECTION, rec);
   }
   ```

3. **Review Header Reference:**

   * For more header ideas, refer to resources like:

     * [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
     * [MDN HTTP Headers Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

---

## Example Use Case

* **Security teams** can use this log to spot outdated or vulnerable web servers.
* **Threat hunters** may look for anomalous or suspicious header values (e.g., servers masquerading as common web servers).

---

## Trying Out the Script on [Try Zeek](https://try.zeek.org/)

You can easily test this script online using the [Try Zeek](https://try.zeek.org/) web sandbox—no local installation required. Here’s how:

1. **Go to [try.zeek.org](https://try.zeek.org/).**

2. **Copy and paste your script** into the left-side script editor.

3. **Add or select sample HTTP traffic:**

   * Click the **“Examples”** button and select “HTTP” to get some sample HTTP events.
   * Or, paste your own log data into the “Events” section.

4. **Click “Execute.”**

   * The script will run, and you will see the output on the right side of the page.
   * Check the **“Logs”** tab for the generated `http_server_detection` log, showing which server headers were detected.


> **Tip:** You can quickly tweak your script and re-run as many times as you want to see how changes affect the output.



## Summary

This script is a lightweight starting point for HTTP response header analysis in Zeek. With minor modifications, it can be adapted to log any combination of HTTP headers required for your analysis.


---
