package id.web.gandos.domain;

import id.web.gandos.util.HttpClient;

import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * Created by rinow on 3/12/2017.
 */
public class PcapHttpSummary {
    private String host = "";
    private HttpClient.METHOD method;
    private String requestBody;
    private String responseCode;
    private String responseBody;

    List<String> requestHeader;
    List<String> requestCookies;

    List<String> responseHeader;
    List<String> responseCookies;

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public HttpClient.METHOD getMethod() {
        return method;
    }

    public void setMethod(HttpClient.METHOD method) {
        this.method = method;
    }

    public void setMethod(String method) {

        switch ( method ) {
            case "GET":
                this.method = HttpClient.METHOD.GET;
                break;

            case "POST":
                this.method = HttpClient.METHOD.POST;
                break;

            case "PUT":
                this.method = HttpClient.METHOD.PUT;
                break;

            case "DELETE":
                this.method = HttpClient.METHOD.DELETE;
                break;

            case "OPTION":
                this.method = HttpClient.METHOD.OPTION;
                break;

            case "HEAD":
                this.method = HttpClient.METHOD.HEAD;
                break;
        }

    }

    public String getRequestBody() {
        return requestBody;
    }

    public void setRequestBody(String requestBody) {

        if( requestBody != null )
            requestBody = requestBody.replaceAll( " ", "" );
        this.requestBody = requestBody;
    }

    public String getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(String responseCode) {
        this.responseCode = responseCode;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody;
    }

    public List<String> getRequestHeader() {
        return requestHeader;
    }

    public void setRequestHeader(List<String> requestHeader) {
        this.requestHeader = requestHeader;
    }

    public List<String> getRequestCookies() {
        return requestCookies;
    }

    public void setRequestCookies(List<String> requestCookies) {
        this.requestCookies = requestCookies;
    }

    public List<String> getResponseHeader() {
        return responseHeader;
    }

    public void setResponseHeader(List<String> responseHeader) {
        this.responseHeader = responseHeader;
    }

    public List<String> getResponseCookies() {
        return responseCookies;
    }

    public void setResponseCookies(List<String> responseCookies) {
        this.responseCookies = responseCookies;
    }

    @Override
    public String toString() {
        StringJoiner sb = new StringJoiner( System.lineSeparator() );

        sb.add( method +" " +host );
        sb.add( "request header: " +requestHeader );
        sb.add( "request cookies: " +requestCookies );
        sb.add( "request boy: " +requestBody);
        sb.add( "response code: " +responseCode );
        sb.add( "response header: " +responseHeader );
        sb.add( "response cookie: " +responseCookies );
        sb.add( "body: " +responseBody );

        return sb.toString();
    }
}
