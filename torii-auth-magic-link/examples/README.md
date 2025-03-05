# Magic Link Example

This example demonstrates how to use the Magic Link plugin to authenticate a user using an email and password.

## Running the example

```bash
cargo run --example magic-link
```

## Accessing the example

The example will start a server on `http://localhost:4000`. You can access the example by opening a browser and navigating to `http://localhost:4000/` and completing the form to create a new user.

Once you have created a user, you can access the example by navigating to `http://localhost:4000/` and clicking the "Get Magic Link" button.

Once signed in, you will be redirected to `http://localhost:4000/whoami` where you can view the user's details.

> [!IMPORTANT]  
> If you run the example multiple times, you will need to clear your cookies or use a different browser to test signing in with a different user.
