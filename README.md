# ecewo-session

A library for session-based authentication for [Ecewo](https://github.com/savashn/ecewo).

## Documentation

```c
// Initialize the session system
int init_sessions(void);

// Clean up and free all session resources
void reset_sessions(void);

// Function to create a new session
// Creates a new session, generates a session ID, and initializes session data
// Returns the session ID if creation is successful, NULL otherwise
Session *create_session(int max_age);

// Function to find a session by its ID
// Searches for a session using the provided session ID
// Returns a pointer to the session if found and not expired, NULL otherwise
Session *find_session(const char *id);

// Function to set a key-value pair in the session's data (stored as JSON)
// Updates the session data (JSON format) with the given key and value
void set_session(Session *sess, const char *key, const char *value);

// Function to free a session and its associated resources
// Clears session ID, expiration time, and frees session data
void free_session(Session *sess);

// Function to get the authenticated session from request cookies
// Extracts the session ID from the cookies in the request headers
// Returns the session if found and authenticated, NULL otherwise
Session *get_session(request_t *headers);

// Print all the registered sessions to the console
void print_sessions(void);

// Send session to the client
void send_session(Res *res, Session *sess);

// Delete the session
void delete_session(Res *res, Session *sess);
```

See the [session chapter](https://ecewo.vercel.app/docs/session) of Ecewo documentation for example usage.
