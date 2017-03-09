package id.web.gandos;

import id.web.gandos.ui.HttpPane;
import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.net.URL;

/**
 * Hello world!
 *
 */
public class App extends Application
{
    public static void main( String[] args )
    {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("OneTool to Rule them all");

        TabPane tabs = new TabPane();

        HttpPane h = new HttpPane();

        Tab tabHttp = new Tab();
        tabHttp.setText( "Http Tool" );
        tabHttp.setContent( h );

        tabs.getTabs().addAll(tabHttp);

        Scene scene = new Scene(tabs, 1000, 800);

        URL url = this.getClass().getResource("/app.css");
        if (url == null) {
            System.out.println("Resource not found. Aborting.");
            System.exit(-1);
        }

        String css = url.toExternalForm();
        scene.getStylesheets().add(css);

        primaryStage.setScene(scene);
        primaryStage.show();
        System.out.println( h.getHeight() );
    }
}
