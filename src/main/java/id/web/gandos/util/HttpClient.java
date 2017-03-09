package id.web.gandos.util;


import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpClient {
	
	public static String get( String url, Map<String, String> headers, String downloadPath ) throws Exception {
		return get( url, headers, downloadPath, null );
	}
	
	public static String get( String url, Map<String, String> headers, String downloadPath, List<Cookie> cookies ) throws Exception {
		return get( url, headers, downloadPath, cookies, null, null );
	}
	
	public static String get( String url, Map<String, String> headers, String downloadPath, List<Cookie> cookies, String proxyIp, String proxyPort ) throws Exception {
		
		System.out.println( "Get Request to: " +url );
		
		StringBuffer sb = new StringBuffer();

		CloseableHttpClient client = HttpClients.custom()
												.setRetryHandler( new HttpRequestRetryHandler() {
													
													@Override
													public boolean retryRequest(IOException arg0, int arg1, HttpContext arg2) {
														// TODO Auto-generated method stub
														return false;
													}
												}).build();

		HttpClientContext context = HttpClientContext.create();
		CloseableHttpResponse response = null;


		BufferedReader rd = null;
		
		try {
			HttpGet request = new HttpGet( url );
			
			if( proxyIp != null && proxyPort != null && !"".equals( proxyIp ) && !"".equals( proxyPort )) {
				HttpHost proxy = new HttpHost( proxyIp, Integer.valueOf( proxyPort ), "http" );
				RequestConfig config = RequestConfig.custom()
		                .setProxy(proxy)
		                .build();
				
				request.setConfig( config );
			}
			
			if( headers != null )
				for( String k : headers.keySet() ) {
					request.addHeader( k, headers.get( k ) );
				}
			
			if( cookies != null ) {
				  BasicCookieStore cookieStore = new BasicCookieStore();
				  
				  for( Cookie c : cookies )
					  cookieStore.addCookie( c );
				  
				  context.setCookieStore( cookieStore );
			  }
				
			response = client.execute(request, context);
	
			if (response.getStatusLine().getStatusCode() != 200 && 
				  response.getStatusLine().getStatusCode() != 201) {
					System.out.println( response.getStatusLine().getReasonPhrase() );
					throw new RuntimeException("Failed : HTTP error code : "
						+ response.getStatusLine().getStatusCode());
				}
			
			// Get the response
			rd = new BufferedReader
			  (new InputStreamReader(response.getEntity().getContent())); 
			
			
			if( downloadPath != null ) {
							
				FileWriter fw = new FileWriter( new File( downloadPath ) );
				
				//char[] buffer = new char[4096]; 
				int n;
				
				while((n = rd.read() ) != -1 ) {
					fw.write( n );
				}
				
				fw.close();
				
				return downloadPath;
			}
			
			String line = "";
			while ((line = rd.readLine()) != null) {
				sb.append(line);
			} 

		} catch (Exception e) {
		      //e.printStackTrace();
		      
		      throw e;
	    } finally {
	      // When HttpClient instance is no longer needed,
	      // shut down the connection manager to ensure
	      // immediate deallocation of all system resources
	    	try {
	    		if(response != null)
	    			response.close();
	    		
	    		if( rd != null )
	    			rd.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();				
			}
	    }
		
		return sb.toString();
	}
	
	
	public static Map<String, Object> post( String url, Map<String,String> headers, String payload, List<Cookie> cookies ) throws Exception {
		return post(url, headers, payload, cookies, null, null );
	}
	
	public static Map<String, Object> post( String url, Map<String,String> headers, String payload, List<Cookie> cookies, String proxyIp, String proxyPort ) throws Exception {
		
		System.out.println( "PostRequest to: " +url );

		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpClientContext context = HttpClientContext.create();
		CloseableHttpResponse response = null;
		
		Map<String, Object> responseData = new HashMap<>();
		String result = "";		


	    try {
	        	
	      // specify the get request
	      HttpPost postRequest = new HttpPost( url );	 
	      StringEntity input = new StringEntity( payload );	 	      
	      
		  postRequest.setEntity(input);
		  
		  if( proxyIp != null && proxyPort != null && !"".equals( proxyIp ) && !"".equals( proxyPort )) {
				HttpHost proxy = new HttpHost( proxyIp, Integer.valueOf( proxyPort ), "http" );
				RequestConfig config = RequestConfig.custom()
		                .setProxy(proxy)
		                .build();
				
				postRequest.setConfig( config );
		  }
		  
		  
		  if( headers != null )
			  for( String k : headers.keySet() ) {
				  postRequest.addHeader( k, headers.get( k ) );
			  }
		  
		  if( cookies != null ) {
			  BasicCookieStore cookieStore = new BasicCookieStore();
			  
			  for( Cookie c : cookies )
				  cookieStore.addCookie( c );
			  
			  context.setCookieStore( cookieStore );
		  }
		  
     	  response = httpclient.execute( postRequest, context );

			if( response.getEntity() != null ) {
				BufferedReader br = new BufferedReader(
						new InputStreamReader((response.getEntity().getContent())));

				String output;

				while ((output = br.readLine()) != null) {
					result += output;
				}
			}

			if (response.getStatusLine().getStatusCode() >= 400 ) {
				//System.out.println( response );
				throw new RuntimeException("Failed : HTTP error code : "
						+ response.getStatusLine().getStatusCode() +", Body: " +result );
			}
		
			Map<String,String> header = new HashMap<>();
			for( Header h : response.getAllHeaders() )
				header.put( h.getName(), h.getValue() );
			
			responseData.put( "code", String.valueOf( response.getStatusLine().getStatusCode()) );
			responseData.put( "header", header );
			responseData.put( "cookies", context.getCookieStore().getCookies() );
			responseData.put( "body", result );
			
	    } catch (Exception e) {
	      e.printStackTrace();
	      throw e;
	    } finally {
	      // When HttpClient instance is no longer needed,
	      // shut down the connection manager to ensure
	      // immediate deallocation of all system resources
	      try {
	    	  if(response != null)
			response.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    }
	    
	    return responseData;
	}
	
	public static String getIp( String url, String proxyIp, String proxyPort ) throws Exception {
		
		System.out.println( "Resolving: " +url );
				
		
		CloseableHttpClient client = HttpClients.custom()
												.setRetryHandler( new HttpRequestRetryHandler() {
													
													@Override
													public boolean retryRequest(IOException arg0, int arg1, HttpContext arg2) {
														// TODO Auto-generated method stub
														return false;
													}
												}).build();
		
		HttpClientContext context = HttpClientContext.create();
		CloseableHttpResponse response = null;
		
		
		BufferedReader rd = null;
		
		try {
			HttpGet request = new HttpGet( url );
			
			if( proxyIp != null && proxyPort != null && !"".equals( proxyIp ) && !"".equals( proxyPort )) {
				HttpHost proxy = new HttpHost( proxyIp, Integer.valueOf( proxyPort ), "http" );
				RequestConfig config = RequestConfig.custom()
		                .setProxy(proxy)
		                .build();
				
				request.setConfig( config );
			}
			
			
				
			response = client.execute(request, context);
	
			InetSocketAddress sockAddress =  (InetSocketAddress) context.getAttribute( "sock-address" );
			
			return sockAddress != null && sockAddress.getAddress() != null ? sockAddress.getAddress().toString() : "";
			
		} catch (Exception e) {
		      //e.printStackTrace();
		      
		      throw e;
	    } finally {
	      // When HttpClient instance is no longer needed,
	      // shut down the connection manager to ensure
	      // immediate deallocation of all system resources
	    	try {
	    		if(response != null)
	    			response.close();
	    		
	    		if( rd != null )
	    			rd.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    }
		
	}
	
	static String USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.59 Safari/537.36";

}
