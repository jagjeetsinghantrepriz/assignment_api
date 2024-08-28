package com.assignm1.wapi;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.impl.JWTAuthProviderImpl;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.handler.JWTAuthHandler;

//import java.nio.Buffer;
import java.util.HashMap;
import java.util.Map;

public class MainVerticle extends AbstractVerticle {

  private JWTAuth jwtAuth;
  private final Map<String, String> users = new HashMap<>(); // In-memory user store

  // OpenWeatherMap API key
  private static final String API_KEY = "9f82b3c0672598ddc0187f850e817bb2"; // Replace with your actual API key

  @Override
  public void start(Promise<Void> startPromise) throws Exception {
    Router router = Router.router(vertx);

    JWTAuthOptions jwtAuthOptions=new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("HS256")
        .setBuffer("keyboard cat"));
    JWTAuth provider=JWTAuth.create(vertx, jwtAuthOptions);
    router.route().path("/api/weather/:city").produces("application/json").handler(JWTAuthHandler.create(provider)).handler(this::handleWeather);
    /*
    // Configure JWT authentication
    KeyStoreOptions keyStoreOptions = new KeyStoreOptions()
      .setType("jks")
      .setPath("keystore.jks")
      .setPassword("your_keystore_password");

    // Set the KeyStoreOptions in JWTAuthOptions
    JWTAuthOptions config = new JWTAuthOptions()
      .setKeyStore(keyStoreOptions);
    jwtAuth = JWTAuth.create(vertx, config);

    // Enable body handling for POST requests
    router.route().handler(BodyHandler.create());
    */
    // Sign-up handler
    router.post("/api/signup").handler(BodyHandler.create()).handler(this::handleSignup);

    // Sign-in handler
    router.post("/api/signin").handler(BodyHandler.create()).handler(
      routingContext->{
        JsonObject userData = routingContext.getBodyAsJson();
        String username = userData.getString("username");
        String password = userData.getString("password");

        if (username == null || password == null) {
          routingContext.response().setStatusCode(400).end("Missing username or password");
          return;
        }

        String storedPassword = users.get(username);
        if (storedPassword == null || !storedPassword.equals(password)) {
          routingContext.response().setStatusCode(401).end("Invalid username or password");
          return;
        }

        //String token = .generateToken(new JsonObject().put("sub", username),
        String token= provider.generateToken(new JsonObject().put("sub", username));
        // new JWTOptions().setExpiresInMinutes(60)); // Token expires in 1 hour
        routingContext.response().putHeader("Authorization", "Bearer " + token)
          .end(new JsonObject().put("token", token).encode());
      }

    );

    // Test protected route
    //router.get("/api/protected").handler(this::handleProtected);

    // Weather route
    //router.get("/api/weather").handler(this::handleWeather);

    vertx.createHttpServer()
      .requestHandler(router)
      .listen(8080, result -> {
        if (result.succeeded()) {
          startPromise.complete();
          System.out.println("HTTP server started on port 8080");
        } else {
          startPromise.fail(result.cause());
        }
      });
  }

  private void handleSignup(RoutingContext routingContext) {
    JsonObject userData = routingContext.getBodyAsJson();
    String username = userData.getString("username");
    String password = userData.getString("password");

    if (username == null || password == null) {
      routingContext.response().setStatusCode(400).end("Missing username or password");
      return;
    }

    if (users.containsKey(username)) {
      routingContext.response().setStatusCode(400).end("User already exists");
      return;
    }

    users.put(username, password);
    routingContext.response().setStatusCode(201).end("Signup successful");
  }

  private void handleSignin(RoutingContext routingContext) {
    JsonObject userData = routingContext.getBodyAsJson();
    String username = userData.getString("username");
    String password = userData.getString("password");

    if (username == null || password == null) {
      routingContext.response().setStatusCode(400).end("Missing username or password");
      return;
    }

    String storedPassword = users.get(username);
    if (storedPassword == null || !storedPassword.equals(password)) {
      routingContext.response().setStatusCode(401).end("Invalid username or password");
      return;
    }

    //String token = .generateToken(new JsonObject().put("sub", username),
    //String token=
    //  new JWTOptions().setExpiresInMinutes(60)); // Token expires in 1 hour
    //routingContext.response().putHeader("Authorization", "Bearer " + token)
    // .end(new JsonObject().put("token", token).encode());
  }

  private void handleProtected(RoutingContext routingContext) {
    String authHeader = routingContext.request().getHeader("Authorization");

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      routingContext.response().setStatusCode(401).end("No token provided");
      return;
    }

    String token = authHeader.substring(7);
    jwtAuth.authenticate(new JsonObject().put("jwt", token), res -> {
      if (res.succeeded()) {
        routingContext.response().end("Access granted");
      } else {
        routingContext.response().setStatusCode(401).end("Invalid token");
      }
    });
  }

  private void handleWeather(RoutingContext routingContext) {
    String city = routingContext.request().getParam("city");
    if (city == null) {
      routingContext.response().setStatusCode(400).end("City parameter is missing");
      return;
    }

    WebClient client = WebClient.create(vertx);
    String url = "/data/2.5/weather?q=" + city + "&appid=" + API_KEY;

    client.get(443, "api.openweathermap.org", url)
      .ssl(true)
      .send(ar -> {
        if (ar.succeeded()) {
          HttpResponse<Buffer> response = ar.result();
          JsonObject weatherData = response.bodyAsJsonObject(); // Convert Buffer to JsonObject
          routingContext.response()
            .putHeader("content-type", "application/json")
            .end(weatherData.encode());
        } else {
          routingContext.response().setStatusCode(500).end("Failed to retrieve weather data");
        }
      });
  }
}

