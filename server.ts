import * as https from "node:https";
import * as fs from "node:fs";
import { initializeApp } from 'firebase/app';
import {
    getAuth,
    createUserWithEmailAndPassword,
    sendPasswordResetEmail,
    signInWithEmailAndPassword,
    deleteUser,
    Auth
} from 'firebase/auth';
import {IncomingMessage, ServerResponse} from "node:http";

const prodConfig = JSON.parse(fs.readFileSync('prod-config.json', 'utf8'));

const stagingConfig = JSON.parse(fs.readFileSync('staging-config.json', 'utf8'));

const prodApp = initializeApp(prodConfig, 'prod');
const stagingApp = initializeApp(stagingConfig, 'staging');

const prodAuth = getAuth(prodApp);
const stagingAuth = getAuth(stagingApp);

// Server configuration
const PORT = 45500;

interface RegisterRequest {
    email: string;
    password: string;
    environment?: 'prod' | 'staging';
}

interface PasswordResetRequest {
    email: string;
    environment?: 'prod' | 'staging';
}

interface DeleteAccountRequest {
    email: string;
    password: string;
    environment?: 'prod' | 'staging';
}

interface SuccessResponse {
    success: boolean;
    message: string;
    data?: any;
}

interface ErrorResponse {
    success: false;
    error: string;
    code?: string;
}

const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
}

// Helper function to get the appropriate auth instance
function getAuthInstance(environment?: 'prod' | 'staging'): Auth {
    return environment === 'staging' ? stagingAuth : prodAuth;
}

// Helper function to parse request body
function parseBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', (chunk: { toString: () => string; }) => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch (error) {
                reject(new Error('Invalid JSON'));
            }
        });
        req.on('error', reject);
    });
}

// Helper function to send JSON response
function sendResponse(res:  ServerResponse<IncomingMessage> & {
    req: IncomingMessage
}, statusCode: number, data: SuccessResponse | ErrorResponse) {
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end(JSON.stringify(data));
}

// Register account handler
async function handleRegister(body: RegisterRequest, res:  ServerResponse<IncomingMessage> & {
    req: IncomingMessage
}) {
    try {
        const { email, password, environment = 'prod' } = body;

        if (!email || !password) {
            sendResponse(res, 400, {
                success: false,
                error: 'Email and password are required'
            });
            return;
        }

        const auth = getAuthInstance(environment);
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);

        console.log(`[${new Date().toISOString()}] Account registered: ${email} (${environment})`);

        sendResponse(res, 200, {
            success: true,
            message: 'Account registered successfully',
            data: {
                uid: userCredential.user.uid,
                email: userCredential.user.email,
                environment
            }
        });
    } catch (error: any) {
        console.error(`[${new Date().toISOString()}] Registration error:`, error.message);

        let errorMessage = 'Registration failed';
        let statusCode = 500;

        if (error.code === 'auth/email-already-in-use') {
            errorMessage = 'Email already in use';
            statusCode = 400;
        } else if (error.code === 'auth/invalid-email') {
            errorMessage = 'Invalid email format';
            statusCode = 400;
        } else if (error.code === 'auth/weak-password') {
            errorMessage = 'Password is too weak';
            statusCode = 400;
        }

        sendResponse(res, statusCode, {
            success: false,
            error: errorMessage,
            code: error.code
        });
    }
}

// Password reset handler
async function handlePasswordReset(body: PasswordResetRequest, res:  ServerResponse<IncomingMessage> & {
    req: IncomingMessage
}) {
    try {
        const { email, environment = 'prod' } = body;

        if (!email) {
            sendResponse(res, 400, {
                success: false,
                error: 'Email is required'
            });
            return;
        }

        const auth = getAuthInstance(environment);
        await sendPasswordResetEmail(auth, email);

        console.log(`[${new Date().toISOString()}] Password reset email sent: ${email} (${environment})`);

        sendResponse(res, 200, {
            success: true,
            message: 'Password reset email sent successfully'
        });
    } catch (error: any) {
        console.error(`[${new Date().toISOString()}] Password reset error:`, error.message);

        let errorMessage = 'Failed to send password reset email';
        let statusCode = 500;

        if (error.code === 'auth/user-not-found') {
            errorMessage = 'No user found with this email';
            statusCode = 404;
        } else if (error.code === 'auth/invalid-email') {
            errorMessage = 'Invalid email format';
            statusCode = 400;
        }

        sendResponse(res, statusCode, {
            success: false,
            error: errorMessage,
            code: error.code
        });
    }
}

// Delete account handler
async function handleDeleteAccount(body: DeleteAccountRequest, res:  ServerResponse<IncomingMessage> & {
    req: IncomingMessage
}) {
    try {
        const { email, password, environment = 'prod' } = body;

        if (!email || !password) {
            sendResponse(res, 400, {
                success: false,
                error: 'Email and password are required'
            });
            return;
        }

        const auth = getAuthInstance(environment);

        // First, sign in to verify credentials
        const userCredential = await signInWithEmailAndPassword(auth, email, password);

        // Then delete the user
        await deleteUser(userCredential.user);

        console.log(`[${new Date().toISOString()}] Account deleted: ${email} (${environment})`);

        sendResponse(res, 200, {
            success: true,
            message: 'Account deleted successfully'
        });
    } catch (error: any) {
        console.error(`[${new Date().toISOString()}] Delete account error:`, error.message);

        let errorMessage = 'Failed to delete account';
        let statusCode = 500;

        if (error.code === 'auth/user-not-found') {
            errorMessage = 'No user found with this email';
            statusCode = 404;
        } else if (error.code === 'auth/wrong-password') {
            errorMessage = 'Invalid password';
            statusCode = 401;
        } else if (error.code === 'auth/invalid-email') {
            errorMessage = 'Invalid email format';
            statusCode = 400;
        } else if (error.code === 'auth/too-many-requests') {
            errorMessage = 'Too many requests. Please try again later';
            statusCode = 429;
        }

        sendResponse(res, statusCode, {
            success: false,
            error: errorMessage,
            code: error.code
        });
    }
}

//Register account, password reset, delete account.
https.createServer(options, async (req, res) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.writeHead(200, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        });
        res.end();
        return;
    }

    // Only allow POST requests
    if (req.method !== 'POST') {
        sendResponse(res, 405, {
            success: false,
            error: 'Method not allowed'
        });
        return;
    }

    try {
        const body = await parseBody(req);

        // Route to appropriate handler based on URL
        switch (req.url) {
            case '/register':
                await handleRegister(body, res);
                break;

            case '/reset-password':
                await handlePasswordReset(body, res);
                break;

            case '/delete-account':
                await handleDeleteAccount(body, res);
                break;

            default:
                sendResponse(res, 404, {
                    success: false,
                    error: 'Endpoint not found. Available endpoints: /register, /reset-password, /delete-account'
                });
                break;
        }
    } catch (error: any) {
        console.error(`[${new Date().toISOString()}] Server error:`, error.message);
        sendResponse(res, 500, {
            success: false,
            error: 'Internal server error'
        });
    }
}).listen(PORT, () => {
    console.log(`Server running at https://localhost:${PORT}`);
    console.log('\nAvailable endpoints:');
    console.log('  POST /register - Register a new account');
    console.log('  POST /reset-password - Send password reset email');
    console.log('  POST /delete-account - Delete an account');
    console.log('\nExample usage:');
    console.log(`  curl -X POST https://localhost:${PORT}/register \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"email":"user@example.com","password":"password123","environment":"prod"}'`);
});