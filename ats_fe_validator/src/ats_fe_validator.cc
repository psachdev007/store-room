/*
 * uuid.c: add header X-Media-Request-Id=UUID
 *
 * Usage:
 *   (Linux): uuid.so
 */

#include <ts/ts.h>
#include <stdio.h>
#include <string.h>
#include <tshttptxnutil.h>
#include <configloader.h>
#include <plugindefines.h>

DEFINE_PLUGIN_NAME(fe_validator);

static const char TS_MIME_FIELD_CARP[] = "ATS-Carp-Routed";
//static const char TS_MIME_FIELD_ACCEPT_ENCODING[] = "Accept-Encoding";
//static const char TS_MIME_FIELD_CONTENT_TYPE[] = "Content-Type";
static const char TS_MIME_FIELD_RESPONSE_VALIDATED[] = "X-Response-Validated";
static const char CONTENT_TYPE_HTML[] = "text/html";
static const char CONTENT_TYPE_TEXT_XML[] = "text/xml";
static const char CONTENT_TYPE_APP_XML[] = "application/xml";
static const char CONTENT_TYPE_MULTI_MIXED[] = "multipart/mixed";
static const char CONTENT_TYPE_JSON[] = "application/json";
#define STATE_BUFFER_DATA   0
#define STATE_OUTPUT_DATA   1
#define TS_HTTP_STATUS_YDOD_ERROR 999
#define EMPTY_BUFFER_LENGTH 0

static TSIOBuffer empty_buffer;
static TSIOBufferReader empty_buffer_reader;

/**
 * To Store the config info for fe validator plugin
 */
struct FeValidatorConf {
    bool strip_accept_encoding;
    std::vector<std::string> allow_request_methods;

    bool loadConfigFile(const char* filename) {
        PLUGINDEBUG("Loading conf file:%s",filename);
        Config cfg;
        FeValidatorConf& feValidatorConf=*this;
        if (!cfg.loadFile(filename)) {
            TSError(PLUGIN_NAME, "Failed to read config file: %s", filename);
            return false;
        }

        PLUGINDEBUG("Config Loaded");
        GETCONFIG(feValidatorConf,cfg,strip_accept_encoding,Bool,true);
        dump();
        return true;
    }

    void dump() {
        if (!fPluginDebug) return;
        PLUGINDEBUG("Config for fe validator plugin");
        PLUGINDEBUG("strip_accept_encoding       : %s",this->strip_accept_encoding?"true":"false");

    }

} feValidatorConf;

/* Data stored for each vconnection*/
typedef struct
{
    int state;
    TSHttpTxn txn;
    TSVIO output_vio;
    TSIOBuffer output_buffer;
    TSIOBufferReader output_reader;
    TSHttpStatus error_code;
    char* error_message;
} VconnData;

/*create new vconnection data*/
static VconnData * vconn_data_alloc(TSHttpTxn txnp)
{
    VconnData *data;

    data = (VconnData *) TSmalloc(sizeof(VconnData));
    data->state = STATE_BUFFER_DATA;
    data->txn = txnp;
    data->output_vio = NULL;
    data->output_buffer = NULL;
    data->output_reader = NULL;
    data->error_message = NULL;
    data->error_code = TS_HTTP_STATUS_NONE;

    return data;
}

/*destroy vconnection data*/
static void vconn_data_destroy(VconnData * data)
{
    if (data) {
        if (data->output_buffer) {
            TSIOBufferDestroy(data->output_buffer);
        }
        if (data->error_message){
            TSfree(data->error_message);
        }
        TSfree(data);
    }
}

static int handle_buffering(TSCont contp, VconnData * data)
{
    TSVIO write_vio;
    int towrite;
    int avail;

    PLUGINDEBUG("In handle_buffering");
    /* Get the write VIO for the write operation that was performed on
     * ourself. This VIO contains the buffer that we are to read from
     * as well as the continuation we are to call when the buffer is
     * empty.
     */
    write_vio = TSVConnWriteVIOGet(contp);

    /* Create the output buffer and its associated reader */
    if (!data->output_buffer) {
        PLUGINDEBUG("Creating output buffer");
        data->output_buffer = TSIOBufferCreate();
        TSAssert(data->output_buffer);
        data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
        TSAssert(data->output_reader);
    }

    /* We also check to see if the write VIO's buffer is non-NULL. A
     * NULL buffer indicates that the write operation has been
     * shutdown and that the continuation does not want us to send 
     * any more WRITE_READY or WRITE_COMPLETE events. For this buffered
     * transformation that means we're done buffering data.
     */

    if (!TSVIOBufferGet(write_vio)) {
        PLUGINDEBUG("Creating input vio is NULL. So upstream continuation is done writing. Time to write buffered data to downstream output vconnection");
        data->state = STATE_OUTPUT_DATA;
        return 0;
    }

    /* Determine how much data we have left to read. For this
     * bnull transform plugin this is also the amount of data we
     * have left to write to the output connection.
     */

    towrite = TSVIONTodoGet(write_vio);
    PLUGINDEBUG("towrite=%d", towrite);
    if (towrite > 0) {
        /* The amount of data left to read needs to be
         * truncated by the amount of data actually in the read
         * buffer. 
         */

        avail = TSIOBufferReaderAvail(TSVIOReaderGet(write_vio));
        PLUGINDEBUG("Only  %d bytes are avaible for now to be readfrom upstream vconnection. So we will write(buffer) this amount first", avail);
        if (towrite > avail) {
            towrite = avail;
        }

        if (towrite > 0) {
            PLUGINDEBUG("Writing(buffering)  %d bytes", towrite);
            /* Copy the data from the read
             * buffer to the input buffer. 
             */
            TSIOBufferCopy(data->output_buffer, TSVIOReaderGet(write_vio), towrite, 0);

            /* Tell the read buffer that we have read the data and
             * are no longer interested in it
             */
            PLUGINDEBUG("Updating upstream vconnection that we have read the available %d byts", towrite);
            TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);

            /* Modify the write VIO to reflect how much data we've
             * completed.
             */
            PLUGINDEBUG("Updating 'ndone' for upstream vconnection");
            TSVIONDoneSet(write_vio, TSVIONDoneGet(write_vio) + towrite);
        }
    }

    /* Now we check the write VIO to see if there is data left
     * to read. 
     */
    if (TSVIONTodoGet(write_vio) > 0) {
        if (towrite > 0) {
            /* Call back the write VIO continuation to let it know that we
             * are ready for more data.
             */
            PLUGINDEBUG("Still more data needs to be read from upstream vconnection. Send TS_EVENT_VCONN_WRITE_READY to upstream vconnection");
            TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_READY, write_vio);
        }
    } else {
        PLUGINDEBUG("Done reading and buffering all data from upstream vconnection. Time to write to downstream vconnection");
        data->state = STATE_OUTPUT_DATA;

        /* Call back the write VIO continuation to let it know that
         * we have completed the write operation. 
         */
        PLUGINDEBUG("Send TS_EVENT_VCONN_WRITE_COMPLETE event to upstream vconnection");
        TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_COMPLETE, write_vio);
    }

    return 1;

    /* If we are in this code path then something is seriously wrong. */
    TSError("[fevalidator-transform] Fatal error in plugin");
    TSReleaseAssert(!"[fevalidator-transform] Fatal error in plugin\n");
    return 0;
}

/*
 * Updates status code, status line and response headers like Cache-Control in
 * case of invalid resposne
 */
static void update_response_on_error(VconnData * data){

    PLUGINDEBUG("In update_response_on_error()");
    if(data != NULL && data->txn != NULL){
        TSHttpTxnUtil serverResponse(data->txn, TSHttpTxnUtil::Server, TSHttpTxnUtil::Resp, PLUGIN_NAME);
        PLUGINDEBUG("ErrorCode=%d, ErrorMessage=%s", data->error_code, data->error_message);
        //Set response code 
        if(data->error_code != TS_HTTP_STATUS_NONE){
            serverResponse.setStatusCode(data->error_code);
            if(data->error_message != NULL){
                //Set status line
                serverResponse.setStatusLine(std::string(data->error_message));
            }

        }

        //Update Cache Control to private
        if (TS_SUCCESS == serverResponse.removeHeaders(TS_MIME_FIELD_CACHE_CONTROL)){
            serverResponse.appendHeader(TS_MIME_FIELD_CACHE_CONTROL, "private,no-cache");
            if (TS_SUCCESS == serverResponse.removeHeaders(TS_MIME_FIELD_EXPIRES)){
                serverResponse.appendHeader(TS_MIME_FIELD_EXPIRES, "-1");
            }
        }
    }
}

/*
 * Validates the response. Sets 'error_code' and 'error_message' in
 * continuation's data if the response is not valid.
 * Returns true if response valid or else returns false
 */
static bool is_response_valid(VconnData * data){

    PLUGINDEBUG("In is_response_valid()");
    if(data != NULL && data->txn != NULL){
        TSHttpTxnUtil serverResponse(data->txn, TSHttpTxnUtil::Server, TSHttpTxnUtil::Resp, PLUGIN_NAME);
        // Get Response status code
        TSHttpStatus responseStatus = serverResponse.getStatusCode();

        // Get 'Content-Type' header value from response headers
        std::string contentType = serverResponse.getHeader(TS_MIME_FIELD_CONTENT_TYPE);
        PLUGINDEBUG("ResponseCode=%d, ContentType=%s", responseStatus, contentType.c_str());

        if ((responseStatus != TS_HTTP_STATUS_OK) && (responseStatus != TS_HTTP_STATUS_NOT_FOUND) && (responseStatus != TS_HTTP_STATUS_YDOD_ERROR)) {
            //Bad response (not 200, 404 or 999), return 500 with empty body
            //Also check it there has been a timeout, if yes log it
            PLUGINDEBUG("Invalid response since response code '%d'is not 200, 404 or 999", responseStatus);
            data->error_code = TS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
            const char* error = "Bad Response Code";
            data->error_message = (char*)TSmalloc(strlen(error)+1);
            strcpy(data->error_message, error);
            return false;

        } else if ((contentType.find(CONTENT_TYPE_HTML) == std::string::npos) && (contentType.find(CONTENT_TYPE_TEXT_XML) == std::string::npos) && (contentType.find(CONTENT_TYPE_APP_XML) == std::string::npos) && (contentType.find(CONTENT_TYPE_MULTI_MIXED)  == std::string::npos) && (contentType.find(CONTENT_TYPE_JSON) == std::string::npos)){ 
            //Bad response (not a valid content type), return 500 with empty body
            PLUGINDEBUG("Invalid response since content type '%s' is not text/html,text/xml,application/xml,application/json or multipart/mixed", contentType.c_str());
            data->error_code = TS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
            const char* error = "Bad Response Content Type";
            data->error_message = (char*)TSmalloc(strlen(error)+1);
            strcpy(data->error_message, error);
            return false;

        } else {
            //Validate response body and send error message accordingly 
            PLUGINDEBUG("For other cases.");
            return true;
        }
    }

    return true;

}

static int handle_output(TSCont contp, VconnData * data)
{
    /* Check to see if we need to initiate the output operation. */
    PLUGINDEBUG("In handle_output()");
    if (!data->output_vio) {
        PLUGINDEBUG("WRITING buffered data to output vconnection");
        TSVConn output_conn;

        /* Get the output connection where we'll write data to. */
        output_conn = TSTransformOutputVConnGet(contp);

        /* Validate Response */
        if(is_response_valid(data)){
            PLUGINDEBUG("Valid Response. Let the response go through");
            data->output_vio =
                TSVConnWrite(output_conn, contp, data->output_reader, TSIOBufferReaderAvail(data->output_reader));

        } else {
            PLUGINDEBUG("Invalid Response. Reset the response code and status");
            /* update response status code, status line and response headers*/
            update_response_on_error(data);
            /* Return back an empty body*/
            data->output_vio = TSVConnWrite(output_conn, contp, empty_buffer_reader, EMPTY_BUFFER_LENGTH);
            TSVIONBytesSet(data->output_vio, 0);
        }

        TSAssert(data->output_vio);
    }
    return 1;
}

static void handle_transform(TSCont contp)
{
    VconnData *data;
    int done;

    /* Get our data structure for this operation. The private data
     * structure contains the output VIO and output buffer. If the
     * private data structure pointer is NULL, then we'll create
     * it and initialize its internals. 
     */

    PLUGINDEBUG("In handle_transform() ");
    data = (VconnData *)TSContDataGet(contp);
    if (!data) {
        PLUGINERROR("Didn't get Continuation's Data. Ignoring Event..");
        return;
    }

    do {
        switch (data->state) {
            case STATE_BUFFER_DATA:
                done = handle_buffering(contp, data);
                break;
            case STATE_OUTPUT_DATA:
                done = handle_output(contp, data);
                break;
            default:
                done = 1;
                break;
        }
    } while (!done);
}

/*
 * Handle events from downstream vconnections
 */
static int fevalidator_transform(TSCont contp, TSEvent event, void *edata)
{
    /* Check to see if the transformation has been closed by a
     *      call to TSVConnClose. */

    PLUGINDEBUG("In fevalidator_transform()");
    if (TSVConnClosedGet(contp)) {
        PLUGINDEBUG("VConnection closed. Destroying continuation. !!");
        vconn_data_destroy((VconnData *)TSContDataGet(contp));
        TSContDestroy(contp);
    } else {
        switch (event) {
            case TS_EVENT_ERROR:
                PLUGINDEBUG("Received TS_EVENT_ERROR event");
                TSVIO write_vio;

                /*
                 * Get the write VIO for the write operation
                 * that was performed on ourself. This VIO
                 * contains the continuation of our parent
                 * transformation.
                 */

                write_vio = TSVConnWriteVIOGet(contp);

                /*
                 * Call back the write VIO continuation to
                 * let it know that we have completed the
                 * write operation.
                 */

                TSContCall(TSVIOContGet(write_vio), TS_EVENT_ERROR, write_vio);
                break;

            case TS_EVENT_VCONN_WRITE_COMPLETE:
                PLUGINDEBUG("Received TS_EVENT_VCONN_WRITE_COMPLETE event");

                /*
                 * When our output connection says that it has
                 * finished reading all the data we've written
                 * to it then we should shutdown the write
                 * portion of its connection to indicate that we
                 * don't want to hear about it anymore.
                 */

                TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
                break;

            case TS_EVENT_VCONN_WRITE_READY:
            default:
                PLUGINDEBUG("Received TS_EVENT_VCONN_WRITE_READY event");
                /*
                 * If we get a WRITE_READY event or any other
                 * type of event (sent, perhaps, because we were
                 * reenabled) then we'll attempt to transform
                 * more data.
                 */
                handle_transform(contp);
                break;
        }
    }

    return 0;
}

/*
 * Check and transform response only if is not a 502 response and it has not
 * already been processed by the FE validator plugin (check header
 * 'X-Response-Validated' 
 */
static bool transformable(TSHttpTxnUtil serverResponse)
{

    // We want to transform(validate) only if it has not been validated yet
    std::string responseValidatedbyFEV = serverResponse.getHeader(TS_MIME_FIELD_RESPONSE_VALIDATED);
    if(responseValidatedbyFEV == "1"){
        PLUGINDEBUG("Transformable=0 .FE response has already been validated by the FE validator. Skipping re-validation!!");
        return false;

    } else {
        // Get Response status code
        TSHttpStatus responseStatus = serverResponse.getStatusCode();
        PLUGINDEBUG("ResponseCode=%d", responseStatus);

        if (responseStatus == TS_HTTP_STATUS_BAD_GATEWAY) {
            // Do nothing for "502" responses.
            PLUGINDEBUG("Transformable=0 . Let the 502 response pass through.");
            return false;

        } else if ((responseStatus == TS_HTTP_STATUS_MOVED_PERMANENTLY) || (responseStatus == TS_HTTP_STATUS_MOVED_TEMPORARILY) || (responseStatus ==  TS_HTTP_STATUS_TEMPORARY_REDIRECT)) {
            //Add/Modify Cache-Control header for 301,302 and 307 response
            PLUGINDEBUG("Transformable=0 . No response transformation needed for 301, 302 and 307. Just add/modify the Cache-Control header if needed");
            std::string cacheControlHeader = serverResponse.getHeader(TS_MIME_FIELD_CACHE_CONTROL);
            if(cacheControlHeader.find("private") == std::string::npos){
                PLUGINDEBUG("Cache-Control was not private, resetting it to 'private,no-cache'");
                if (TS_SUCCESS == serverResponse.removeHeaders(TS_MIME_FIELD_CACHE_CONTROL)){
                    serverResponse.appendHeader(TS_MIME_FIELD_CACHE_CONTROL, "private,no-cache");
                    if (TS_SUCCESS == serverResponse.removeHeaders(TS_MIME_FIELD_EXPIRES)){
                        serverResponse.appendHeader(TS_MIME_FIELD_EXPIRES, "-1");
                    }
                }
            }
            return false;
        }
    }

    /* return true for rest of the cases */
    return true; 
}

/*
 * Creates a transform (vconnection) and attaches it to the response tranform
 * hook
 */
static void transform_add(TSHttpTxn txnp)
{
    TSVConn connp;
    VconnData *data;

    connp = TSTransformCreate(fevalidator_transform, txnp);
    data = vconn_data_alloc(txnp);
    TSContDataSet(connp, data);
    TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
    return;
}

/*
 * Adds the tranform if the response is transformable
 */
static int transform_response(TSCont contp, TSHttpTxn txnp)
{

    TSHttpTxnUtil serverResponse(txnp, TSHttpTxnUtil::Server, TSHttpTxnUtil::Resp, PLUGIN_NAME);
    if (transformable(serverResponse)) {
        PLUGINDEBUG("Transformable=1. Response needs transformation");
        transform_add(txnp);
    }

    //Add 'X-Response-Validated' header to ensure that the response is not
    //validated again downstream
    if (TS_SUCCESS == serverResponse.removeHeaders(TS_MIME_FIELD_RESPONSE_VALIDATED)){
        serverResponse.appendHeader(TS_MIME_FIELD_RESPONSE_VALIDATED,"1"); 
    }

    RETURN_SUCCESS(txnp);
}

/*
 * Processes incoming request only when request already been CARP routed (check
 * header 'ATS-Carp-Routed')
 * 1) Strips 'Accept-Encoding' header if present so that FE responds back with
 * non-encoded data
 */
static int process_request(TSCont contp, TSHttpTxn txnp) {

    TSHttpTxnUtil clientRequest(txnp, TSHttpTxnUtil::Client, TSHttpTxnUtil::Req, PLUGIN_NAME);
    std::string carpHeader = clientRequest.getHeader(TS_MIME_FIELD_CARP);
    //check if it is a CARPed request
    if(!carpHeader.empty()){
        PLUGINDEBUG("CARP header found, so activating FE validator");
        //strip accept-encoding header if needed
        if (feValidatorConf.strip_accept_encoding)
        {
            PLUGINDEBUG("Stripping Accept-Encoding Header");
            clientRequest.removeHeaders(TS_MIME_FIELD_ACCEPT_ENCODING);
        }        
    } else {
        PLUGINDEBUG("CARP header NOT found, skipping FE validator");
    }

    RETURN_SUCCESS(txnp);
}

static int plugin_handler(TSCont contp, TSEvent event, void *edata) {
    TSHttpTxn txnp = (TSHttpTxn) edata;
    switch (event) {
        case TS_EVENT_HTTP_POST_REMAP:
            return process_request(contp,txnp);
        case TS_EVENT_HTTP_READ_RESPONSE_HDR:
            return transform_response(contp,txnp);
        default:
            break;
    }

    RETURN_SUCCESS(txnp);
}

/* Plugin Init */
void TSPluginInit(int argc, const char *argv[]) {
    INIT_PLUGIN_DEBUG();
    PLUGINDEBUG("fe validator plugin init");

    if (argc>=2) {
        feValidatorConf.loadConfigFile(argv[1]);
    }
    else {
        feValidatorConf.loadConfigFile("/home/y/conf/ats_fe_validator/ats_fe_validator.conf");
    }

    empty_buffer = TSIOBufferCreate();
    empty_buffer_reader = TSIOBufferReaderAlloc(empty_buffer);

    TSCont contp;
    contp = TSContCreate(plugin_handler, NULL);
    TSHttpHookAdd(TS_HTTP_POST_REMAP_HOOK, contp);
    TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
}
