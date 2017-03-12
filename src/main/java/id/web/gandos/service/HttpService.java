package id.web.gandos.service;

import id.web.gandos.domain.PcapHttpSummary;
import id.web.gandos.util.HttpClient;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jsoup.Jsoup;
import org.jsoup.examples.HtmlToPlainText;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by rinow on 3/11/2017.
 */
public class HttpService {

    public Map<String,Object> sendRequest(String url, HttpClient.METHOD method, Map<String, String> header, String payload,
                                      Map<String,String> cookies, boolean proxy, boolean noSsl ) {

        Map<String,Object> response = null;

        List<Cookie> reqCookies = null;

        if( cookies != null ) {
            reqCookies = new ArrayList<>();

            for( String k : cookies.keySet() )
                reqCookies.add( new BasicClientCookie( k, cookies.get( k ) ) );
        }



        response = HttpClient.sendRequest( url, method, header, payload, reqCookies, null, null );

        if( response.get( "body" ) != null ) {
            response.put( "body", Jsoup.parse( (String) response.get( "body" ) ).body().html() );
        }

        if( response.get( "cookies" ) != null ) {

            List<Cookie> respCookies = (List<Cookie>) response.get( "cookies" );

            Map<String, String> resCookies = new HashMap<>();

            for( Cookie c : respCookies )
                resCookies.put( c.getName(), "value: " +c.getValue() +", domain: " +c.getDomain() +", expiry: " +c.getExpiryDate() );

            response.put( "cookies", resCookies );
        }

        return response;
    }

    public PcapHttpSummary extractPcap( String filePath ) {

        PcapHttpSummary result = new PcapHttpSummary();

        final StringBuilder errbuf = new StringBuilder(); // For any error msgs

        Pcap pcap = Pcap.openOffline( filePath, errbuf );

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return null;
        }

        final Http http = new Http();

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {

                if( packet.hasHeader( http )) {
                    String hexDump =  packet.toHexdump();

                    StringBuffer sb = new StringBuffer();

                    for( String s : hexDump.split( "\\R" ) ) {
                        sb.append( s.substring( s.indexOf( "    " ) + 4 ) );
                    }


                    String payload = sb.toString();

                    //System.out.println( payload );

                    //check request pattern "method /url http-version"
                    Matcher m = REQ_START_PATTERN.matcher( payload );

                    if( m.find() && result.getMethod() == null) {
                        String g = m.group();
                        payload = payload.substring( m.start() + g.length() );

                        g = g.replaceAll( "\\.\\.", "" );
                        String[] s = g.split( " " );

                        if( s != null && s.length >= 2 ) {
                            result.setMethod( s[0] );
                            result.setHost( s[1] );
                        }

                        //check request patter "host: hostname"
                        m = REQ_HOST_PATTERN.matcher( payload );

                        if( m.find() ) {
                            g = m.group();
                            payload = payload.replace( g, "" );

                            g = g.replaceAll( "\\.\\.", "" );
                            s = g.split( ":" );

                            if( s != null && s.length >= 2 )
                                result.setHost( s[1].trim() +result.getHost() );
                        }

                        //check request cookies
                        m = REQ_COOKIE_PATTERN.matcher( payload );

                        if( m.find() ) {
                            g = m.group();
                            payload = payload.replace( g, "" );
                            g = g.replace( "..Cookie:", "" );

                            s = g.split( ";" );

                            if( s != null ) {
                                List<String> rc = new ArrayList<>();

                                for (String c : s) {
                                    rc.add( c );
                                }

                                result.setRequestCookies( rc );
                            }
                        }

                        int idx = payload.indexOf( "...." );

                        if( idx > 0 ) {
                            if( payload.length() >= idx + 4 )
                                result.setRequestBody( payload.substring( idx + 4 ) );
                            else
                                result.setRequestBody( payload.substring( idx) );

                            payload = payload.substring( 0, idx );
                        }

                        s = payload.split( "\\.\\." );


                        if( s != null ) {
                            List<String> rh = new ArrayList<>();

                            for( String h : s )
                                rh.add( h );

                            result.setRequestHeader( rh );
                        }


                    }

                    m = RES_START_PATTERN.matcher( payload );

                    if( m.find() && result.getResponseHeader() == null ) {
                        payload = payload.substring( m.start() );

                        int idx = payload.indexOf( "...." );

                        String header = payload.substring( 0, idx );

                        List<String> rh = new ArrayList<>();

                        String[] h = header.split( "\\.\\." );

                        if( h != null )
                            for( String s : h )
                                rh.add( s );

                        result.setResponseHeader( rh );

                        idx = payload.length() >= idx + 4 ? idx + 4 : idx;

                        result.setResponseBody( payload.substring( idx ) );
                    }

                }
                /*System.out.printf("Received at %s caplen=%-4d len=%-4d : %s %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(), // Length actually captured
                        packet.getCaptureHeader().wirelen(), // Original length
                        packet.toHexdump(),
                        user // User supplied object
                );*/
            }
        };

        try {
            pcap.loop(-1, jpacketHandler, "jNetPcap rocks!");
        } finally {
            /***************************************************************************
             * Last thing to do is close the pcap handle
             **************************************************************************/
            pcap.close();
        }

        return result;
    }

    public static void main(String[] args) {

        final String filePath = "D:\\Code\\jnetpcap\\8.28.16.207.pcap";

        HttpService hs = new HttpService();
        PcapHttpSummary p = hs.extractPcap( filePath );

        System.out.println( p );

        //String input = ".>.J...V'M....E..=hs@....(...rg1...l.P...}.K..P...^...GET /home?ga=123&ss=222 HTTP/1.1..Host: www.detik.com..Connection: keep-alive..Upgrade-Insecure-Requests: 1..User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36..Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8..Accept-Encoding: gzip, deflate, sdch..Accept-Language: en-US,en;q=0.8..Cookie: __utma=146380193.1059462800.1479395630.1479395633.1479395633.1; __utmz=146380193.1479395633.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); _ga=GA1.2.1059462800.1479395630; __dtma=146380193.1708452740.1479396244.1482623752.1489218983.20; __asc=128abd2e15abc5e50457ce98d00; __auc=75c0cf7215872d9e9d1e968b1e7; __dtmb=146380193.3.10.1489219451; dts-=_d%3D.; chs-=d058b23586d898496c23cd7a14b654b0.               .DNT: 1....     ";
        /*String input = ".V'M...>.J....E....c@.....g1.....r.P.l.K......P.^U. ..HTTP/1.1 200 OK..Server: nginx/id26..Date: Sat, 11 Mar 2017 08:05:51 GMT..Content-Type: text/html..Transfer-Encoding: chunked..Connection: keep-alive..Keep-Alive: timeout=10..Cache-Control: no-transform..Vary: User-Agent, Accept..ServerLoc: id26..X-Cached: EXPIRED..X-XSS-Protection: 1;mode=block..X-Content-Type-Options: nosniff..Access-Control-Allow-Origin: *..Content-Encoding: gzip....600a..\u001F...........i{............;....#...l+.d=..............JV....[...$A..`)..>+.H.....5...wNh'...u.^...O.?.......A.....m.*.....0pw............w.....3.t.xW^....\\.b..o'~...%..0...._...._....]^..........~.....;..n.w.(..e.4...9..;l..;,.0N.=..v0.`...0~..........0.lo...-..~.W.a........x6..=./.......5...M.X<$1..Ed...l,/...M.Q.%.....TNI.S.MLfw.(v...0..F.K...$.@q....{..+....ao`&...%Z.........i!_d..t...a..A}.....}.f.FI....I:{.{.............6.wO.U...?......];.1..a].........................,.z..h.e....J4..U...a....6..O,..>..r.{.......F..L.d...7Jn.J.4...d.(.m\"...c?q/...{.;..M<..>..;......=...lJ..m;.]>......N......q.[,....g>.q.sa...}.....v.-U.F........g.}.e.8.o...um70...M.....7..:.....>d...;.,../...}...0....0...!.p..c...\u001F.g.>x&..f..[07r......F.....^.j......n...fM...n..Js...&.6.........j.VkV.o...u..E.e.j..^'q\u001F.t....b.........N~....\u001F..!b....6......z...J.MI.M...V....y.~.a^.......#f.M>.C2.e..(..h.....K.uoo.../....6...va..^..r?........h....m?..h....tp..M?.4%........l....>C.......p.;-.....e.Q^...^..n/.3j..R....N....?..p...19..Mv..I..4c..n....Y..r3...S.8i..s5w..1t1                  ..........      ";
        Matcher m = RES_START_PATTERN.matcher( input );

        if( m.find() ) {
            System.out.println( m.start() +" : " +m.group() );
        }*/

       /* String negatePattern = "^(?!.*(\\.\\.)).*$";

        System.out.println( ".".matches( negatePattern ));*/
    }

    static Pattern REQ_START_PATTERN;
    static Pattern REQ_HOST_PATTERN;
    static Pattern REQ_COOKIE_PATTERN;
    static Pattern RES_START_PATTERN;

    static String REQ_START_REGEX = "\\.\\.(GET|POST|PUT|DELETE|OPTION|HEAD) /[^ ]* HTTP/1\\.[0|1]\\.\\.";
    static String REQ_HOST_REGEX = "(\\.\\.)?Host:(.*?(\\.\\.))";
    static String REQ_COOKIE_REGEX = "\\.\\.Cookie:(.*?(\\.\\.\\.\\.))";
    static String RES_START_REGEX = "HTTP/1\\.[0-1](.*?(\\.\\.))";

    static {
        REQ_START_PATTERN = Pattern.compile( REQ_START_REGEX );
        REQ_HOST_PATTERN = Pattern.compile( REQ_HOST_REGEX );
        REQ_COOKIE_PATTERN = Pattern.compile( REQ_COOKIE_REGEX );
        RES_START_PATTERN = Pattern.compile( RES_START_REGEX );
    }
}
