// Utility functions to handle base64 encoding/decoding for ArrayBuffer
function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
    if (typeof base64 !== 'string') {
        console.error('Invalid base64 input:', base64);
        throw new Error('Invalid base64 input');
    }

    // Replace URL-safe base64 characters if necessary
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/');

    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Generate a random challenge for WebAuthn
function generateRandomChallenge(length) {
    const challenge = new Uint8Array(length);
    window.crypto.getRandomValues(challenge);
    return challenge;
}

// Open or create IndexedDB
const openDatabase = () => {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('webauthn-demo', 1);
       
        request.onupgradeneeded = event => {
            const db = event.target.result;
            let userStore;
            if(db.objectStoreNames.contains('users')){
                userStore=event.target.transaction.objectStore('users');
            }else{
                userStore=db.createObjectStore('users', { keyPath: 'id', autoIncrement: true });
            }

            if (userStore.indexNames.contains('username')) {
                userStore.deleteIndex('username');
            }
            userStore.createIndex('username', 'username', { unique: false });
        };
        request.onsuccess = event => resolve(event.target.result);
        request.onerror = event => reject(event.target.error);
    });
};

// Store user credential in IndexedDB
const storeUser = (db, data) => {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(['users'], 'readwrite');
        const store = transaction.objectStore('users');
        // const request = store.put({ id, ...data });
        const request =store.add(data);
        request.onsuccess = () => resolve();
        request.onerror = event => reject(event.target.error);
    });
};

// Helper function to get user credentialID by username
const getUserByUsername = (db, username) => {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(['users'], 'readonly');
        const store = transaction.objectStore('users');
        const index = store.index('username');
        const request = index.getAll(username);
        request.onsuccess = event => resolve(event.target.result);
        request.onerror = event => reject(event.target.error);
    });
};

// Register Passkey
document.getElementById('register').addEventListener('click', async () => {
    try {
        const db = await openDatabase();

        // Retrieve username from input field
        const username = document.getElementById('username').value.trim();
        if (!username) {
            document.getElementById('result').textContent = 'Username is required for registration.';
            return;
        }

        // Create a new random challenge
        const challenge = generateRandomChallenge(32);

        // Setup PublicKeyCredentialCreationOptions
        const publicKey = {
            challenge: challenge,
            rp: {
                name: "Passkey Demo"
            },
            user: {
                id: Uint8Array.from(window.atob("MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII="), c => c.charCodeAt(0)),
                name: username,
                displayName: username
            },
            pubKeyCredParams: [
                { type: "public-key", alg: -7 }, // ES256
                { type: "public-key", alg: -257 } // RS256
            ],
            authenticatorSelection: {
                userVerification: "preferred" // Prefer user verification if available
            },
            timeout: 60000, // 1 minute
            excludeCredentials: [],
        };

        // Create Passkey
        const credential = await navigator.credentials.create({ publicKey });
        if (!credential) {
            console.error('Failed to create credential');
            return;
        }

        // Generate a sequential ID based on the number of stored users
        const transaction = db.transaction(['users'], 'readwrite');
        const store = transaction.objectStore('users');
        const countRequest = store.count();

        countRequest.onsuccess = async function() {
            const sequentialId = countRequest.result + 1;

            // Store credential in IndexedDB
            await storeUser(db, {
                sequentialId: sequentialId,
                username: username,
                credentialId: bufferToBase64(credential.rawId),
                challenge: bufferToBase64(challenge)
            });

            document.getElementById('result').textContent = 'Registration successful!';
        };
        countRequest.onerror = function() {
            console.error('Error counting users in the database.');
            document.getElementById('result').textContent = 'Registration failed due to database error.';
        };
       
    } catch (error) {
        console.error('Registeration error',error);
        document.getElementById('result').textContent = 'Registration failed.';
    }
});


// Login with Passkey
document.getElementById('login').addEventListener('click', async () => {
    try {
        const db = await openDatabase();

        const username = document.getElementById('username').value.trim();
        if (!username) {
            document.getElementById('result').textContent = 'Username is required for login.';
            return;
        }

        // Retrieve stored user credential
        const storedUsers = await getUserByUsername(db, username);

        console.log('Retrieved stored user:', storedUsers);
        console.log('Username entered:', username);
        console.log('Database record:', storedUsers);
        

         //  Check storedUser is valid
         if (!storedUsers || storedUsers.length === 0) {
            console.error('No valid stored user found.');
            document.getElementById('result').textContent = 'Login failed: No valid stored user found.';
            return;
        }

        // Generate a new challenge for this login attempt
        const newChallenge = generateRandomChallenge(32);

        // Prepare the list of allowed credentials 
        const allowCredentials = [];
        for (let i = 0; i < storedUsers.length; i++) {
            const storedUser = storedUsers[i];
            allowCredentials.push({
                id: base64ToBuffer(storedUser.credentialId),
                type: 'public-key',
            });
        }

        const publicKey = {
            challenge: newChallenge,
            allowCredentials: allowCredentials, // Use the list of credentials
            userVerification: "preferred", // Prefer user verification if available
            timeout: 60000 // 1 minute
        };

        try {
            // Request credential
            const assertion = await navigator.credentials.get({ publicKey });

            console.log('Login successful with one of the credentials');
            document.getElementById('result').textContent = 'Login successful!';

            // Update the challenge in the database for the matched credential
            const matchedUser = storedUsers.find(storedUser =>
                bufferToBase64(assertion.rawId) === storedUser.credentialId
            );

            if (matchedUser) {
                matchedUser.challenge = bufferToBase64(newChallenge);
                const transaction = db.transaction(['users'], 'readwrite');
                const store = transaction.objectStore('users');
                store.put(matchedUser);
            }

            // Redirect to new page upon successful login
            window.location.href = 'main.html';

        } catch (error) {
            console.error('Login failed', error);
            document.getElementById('result').textContent = 'Login failed: No matching credential found.';
        }

    } catch (error) {
        console.error(error);
        document.getElementById('result').textContent = 'Login failed.';
    }
});




