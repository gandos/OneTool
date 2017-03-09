package id.web.gandos.ui;


import javafx.concurrent.Service;
import javafx.concurrent.Task;
import javafx.concurrent.WorkerStateEvent;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
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

		tabReq.getTabs().addAll( tabHeader, tabPayload );

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
		//add( new Label( "gandos jos" ), 0, 7 );

        setHgrow( hbUrl, Priority.ALWAYS );
		setVgrow( vbRes, Priority.ALWAYS  );
	}
}
