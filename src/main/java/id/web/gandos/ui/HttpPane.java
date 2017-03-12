package id.web.gandos.ui;


import id.web.gandos.domain.PcapHttpSummary;
import id.web.gandos.service.HttpService;
import id.web.gandos.util.HttpClient;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import javafx.concurrent.WorkerStateEvent;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.event.EventType;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.input.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class HttpPane extends GridPane {

	public HttpPane() {
		
		setHgap(10);
        setVgap(12);

        Label lbUrl = new Label( "Url" );
        lbUrl.setPrefWidth( 75 );

        TextField tfUrl = new TextField();

		Button btnGo = new Button( "Go" );

		HBox hbUrl = new HBox( 10 );
		hbUrl.getChildren().addAll( lbUrl, tfUrl, btnGo );
		hbUrl.setHgrow( tfUrl, Priority.ALWAYS );

		setMargin( hbUrl, new Insets( 10, 10, 0, 10 ) );

        Label lbMethod = new Label( "Method" );
		lbMethod.setPrefWidth( 75 );
        
        ToggleGroup tgMethod = new ToggleGroup();
        
        RadioButton rbGet = new RadioButton( "Get" );
		rbGet.setSelected( true );
		rbGet.setToggleGroup( tgMethod );
        
        RadioButton rbPost = new RadioButton( "Post" );
		rbPost.setToggleGroup( tgMethod );

		RadioButton rbPut = new RadioButton( "Put" );
		rbPut.setToggleGroup( tgMethod );

		RadioButton rbOption = new RadioButton( "Option" );
		rbOption.setToggleGroup( tgMethod );

		RadioButton rbDelete = new RadioButton( "Delete" );
		rbDelete.setToggleGroup( tgMethod );

        HBox hbMethod = new HBox( 10 );
		hbMethod.getChildren().addAll( lbMethod, rbGet, rbPost, rbPut, rbOption, rbDelete );
        
        setMargin( hbMethod, new Insets( 0, 10, 0, 10 ) );

        CheckBox cbProxy = new CheckBox( "Use Proxy" );
        CheckBox cbSsl = new CheckBox( "Ignore Certificate" );

		HBox hbCheckbox = new HBox();
		hbCheckbox.getChildren().addAll( cbProxy, cbSsl );
		hbCheckbox.setSpacing( 10 );

		setMargin( hbCheckbox, new Insets( 0, 10, 0, 10 ) );

        TextArea taHeader = new TextArea();
		taHeader.setPrefRowCount( 10 );

		TextArea taPayload = new TextArea();
		taPayload.setPrefRowCount( 10 );

		TextArea taCookies = new TextArea();
		taCookies.setPrefRowCount( 10 );

		TabPane tabReq = new TabPane();
		tabReq.setStyle( "my-tab-header-background : white" );

		Tab tabHeader = new Tab();
		tabHeader.setText( "Header" );
		tabHeader.setContent( taHeader );
		tabHeader.setClosable( false );

		Tab tabPayload = new Tab();
		tabPayload.setText( "Body" );
		tabPayload.setContent( taPayload );
		tabPayload.setClosable( false );

		Tab tabCookei = new Tab();
		tabCookei.setText( "Cookies" );
		tabCookei.setContent( taCookies );
		tabCookei.setClosable( false );

		tabReq.getTabs().addAll( tabHeader, tabPayload, tabCookei );

		setMargin( tabReq, new Insets( 0, 10, 0, 10 ) );

		Label lbResponse = new Label( "Response" );

		TextArea taRsHeader = new TextArea();
		taRsHeader.setPrefRowCount( 10 );

		TextArea taRsPayload = new TextArea();
		taRsPayload.setPrefRowCount( 10 );

		TextArea taRsCookies = new TextArea();
		taRsCookies.setPrefRowCount( 10 );

		TabPane tabRes = new TabPane();
		tabRes.setStyle( "my-tab-header-background : white" );

		Tab tabRsPayload = new Tab();
		tabRsPayload.setText( "Body" );
		tabRsPayload.setContent( taRsPayload );
		tabRsPayload.setClosable( false );

		Tab tabRsHeader = new Tab();
		tabRsHeader.setText( "Header" );
		tabRsHeader.setContent( taRsHeader );
		tabRsHeader.setClosable( false );

		Tab tabRsCookies = new Tab();
		tabRsCookies.setText( "Cookies" );
		tabRsCookies.setContent( taRsCookies );
		tabRsCookies.setClosable( false );

		tabRes.getTabs().addAll( tabRsPayload, tabRsHeader, tabRsCookies );

		VBox vbRes = new VBox();
		vbRes.getChildren().addAll( lbResponse, tabRes );
		vbRes.setVgrow( tabRes, Priority.ALWAYS );

		setMargin( vbRes, new Insets( 10, 10, 10, 10 ) );

        add( hbUrl, 0, 0 );
        add( hbMethod, 0, 1 );
		add( tabReq, 0, 2 );
		add( hbCheckbox, 0, 3 );
		add( vbRes, 0, 4  );

		HttpService svc = new HttpService();

		btnGo.setOnAction( e -> {

			StringJoiner errorMsg = new StringJoiner( System.lineSeparator() );

			String url = tfUrl.getText();
			String body = taPayload.getText();

			Map<String, String> reqHeader = null;
			Map<String, String> reqCookies = null;

			String rawHeader = taHeader.getText();
			String rawCookies = taCookies.getText();

			if( rawHeader != null && !"".equals( rawHeader ) ) {
				reqHeader = new HashMap<>();
				String[] headerArr = rawHeader.split( "\\R" );

				for( String h : headerArr ) {
					String[] o = h.split( ":" );

					if( o == null || o.length != 2 )
						errorMsg.add( "Invalid Header Value: " +h );
					else
						reqHeader.put( o[0].trim(), o[1].trim() );
				}
			}

			if( rawCookies != null && !"".equals( rawCookies ) ) {
				reqCookies = new HashMap<>();
				String[] cookiesArr = rawCookies.split( "\\R" );

				for( String c : cookiesArr ) {
					String[] o = c.split( ":" );

					if( o == null || o.length != 2 )
						errorMsg.add( "Invalid Cookie Value: " +c );
					else
						reqCookies.put( o[0].trim(), o[1].trim() );
				}
			}

			HttpClient.METHOD method = rbDelete.isSelected() ? HttpClient.METHOD.DELETE : rbGet.isSelected() ? HttpClient.METHOD.GET :
									   rbOption.isSelected() ? HttpClient.METHOD.OPTION : rbPost.isSelected() ? HttpClient.METHOD.POST :
											   HttpClient.METHOD.PUT;

			if( url == null || "".equals( url ) )
				errorMsg.add( "Please enter URL !" );

			if( errorMsg.length() > 0 ) {
				Alert errorAlert = new Alert( AlertType.ERROR );
				errorAlert.setContentText( errorMsg.toString() );
				errorAlert.show();
			}
			else {
				Map<String,Object> response = svc.sendRequest( url, method, reqHeader, body, reqCookies, cbProxy.isSelected(), cbSsl.isSelected() );

				String code = response.get( "code" )  != null ? ((Integer) response.get( "code" )).toString() : "";

				lbResponse.setText( "Response " +code );
				taRsPayload.setText( (String) response.get( "body" ) );

				if( response.get( "header" ) != null ) {
					Map<String,String> rsHeader = (Map<String,String>) response.get( "header" );

					StringJoiner sj = new StringJoiner( System.lineSeparator() );

					for( String s : rsHeader.keySet() )
						sj.add( s +": " +rsHeader.get( s ) );

					taRsHeader.setText( sj.toString() );
				}

				if( response.get( "cookies" ) != null ) {
					Map<String,String> rsCookies = (Map<String,String>) response.get( "cookies" );

					StringJoiner sj = new StringJoiner( System.lineSeparator() );

					for( String s : rsCookies.keySet() )
						sj.add( s +"= " +rsCookies.get( s ) );

					taRsCookies.setText( sj.toString() );
				}
			}
		});

		setOnDragOver( e -> {
			final Dragboard db = e.getDragboard();

			final boolean isAccepted = db.getFiles().get(0).getName().toLowerCase().endsWith(".pcap");

			if (db.hasFiles()) {
				if (isAccepted) {
					/*HttpPane.this.setStyle("-fx-border-color: red;"
							+ "-fx-border-width: 5;"
							+ "-fx-background-color: #C6C6C6;"
							+ "-fx-border-style: solid;");*/

					e.acceptTransferModes(TransferMode.COPY);
				}
			} else {
				e.consume();
			}
		});

		setOnDragDropped( e -> {
			final Dragboard db = e.getDragboard();

			final boolean isAccepted = db.getFiles().get(0).getName().toLowerCase().endsWith(".pcap");

			if( db.hasFiles() && isAccepted ) {
				PcapHttpSummary sum = svc.extractPcap( db.getFiles().get(0).getAbsolutePath() );

				//System.out.println( sum );

				if( sum == null )
					return;

				tfUrl.setText( sum.getHost() );

				rbGet.setSelected( sum.getMethod() == HttpClient.METHOD.GET );
				rbPost.setSelected( sum.getMethod() == HttpClient.METHOD.POST );
				rbPut.setSelected( sum.getMethod() == HttpClient.METHOD.PUT );
				rbDelete.setSelected( sum.getMethod() == HttpClient.METHOD.DELETE );
				rbOption.setSelected( sum.getMethod() == HttpClient.METHOD.OPTION );

				StringJoiner sj = new StringJoiner( System.lineSeparator() );

				if( sum.getRequestHeader() != null )
					for( String s : sum.getRequestHeader() )
						sj.add( s );

				taHeader.setText( sj.toString());

				taPayload.setText( sum.getRequestBody() );

				sj = new StringJoiner( System.lineSeparator() );

				if( sum.getRequestCookies() != null )
					for( String s : sum.getRequestCookies() )
						sj.add( s );

				taCookies.setText( sj.toString() );

				taRsPayload.setText( sum.getResponseBody() );

				sj = new StringJoiner( System.lineSeparator() );

				if( sum.getResponseHeader() != null )
					for( String s : sum.getResponseHeader() )
						sj.add( s );

				taRsHeader.setText( sj.toString() );
			}
		});

        setHgrow( hbUrl, Priority.ALWAYS );
		setVgrow( vbRes, Priority.ALWAYS  );
	}

	public static void main(String[] args) {
		String[] gaga = "blablabla\nasow\ndadada".split( "\\R" );

		System.out.println( "  sdsdsd  ".trim() );
		System.out.println( gaga.length );
	}
}
