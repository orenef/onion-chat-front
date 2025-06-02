import React, { useState, useEffect, useRef } from "react";
const namesList = [
    "Alex", "Jordan", "Taylor", "Casey", "Morgan", "Skyler", "Jamie", "Riley", "Drew", "Avery",
    "Cameron", "Quinn", "Reese", "Logan", "Dakota", "Phoenix", "Blake", "Jesse", "Charlie", "Alexis",
    "Rowan", "Parker", "Harley", "Frankie", "Elliot", "Finley", "Emerson", "Sam", "Sage", "Robin",
    "Terry", "Corey", "Marley", "Jordan", "Brooklyn", "Adrian", "Spencer", "Hayden", "Shay", "Taylor",
    "Leslie", "Devon", "Kai", "Dallas", "Kendall", "Shannon", "Carter", "Peyton", "Sky", "Jayden"
];

const predefinedMessages = [
  "I loved the demo 🎉",
  "The best talk I've ever attended",
  "What is an onion",
  "A live demo – what a brave move",
  "like",
  "wow"
];

function sanitizeMessage(decryptedPayload) {
    let m = decryptedPayload?.split(':')[1] || "";
    m = m.trim().replace(/^"+|"+$/g, "");
    if (!predefinedMessages.includes(m)) {
        return "What is an onion";
    }
  return decryptedPayload;
}

const generateUserName = () => {
    const randomName = namesList[Math.floor(Math.random() * namesList.length)];
    const randomSuffix = Math.random().toString(36).substring(2, 6);
    return `${randomName}_${randomSuffix}`;
};

const generateKeyPair = async () => {
    return await window.crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
    );
};

const generateSymmetricKey = async () => {
    return await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
};

const encryptWithPublicKey = async (publicKey, data) => {
    try {
        console.log("🔹 Encrypting with Public Key:", publicKey);
        console.log("🔹 Data before encryption:", data);

        if (!(publicKey instanceof CryptoKey)) {
            throw new Error("Invalid publicKey: Not a CryptoKey object!");
        }

        const exportedKey = await window.crypto.subtle.exportKey("raw", data);

         const encryptedData = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            exportedKey
        );

        console.log("✅ Encryption successful!");
        return encryptedData;
    } catch (error) {
        console.error("❌ Encryption failed:", error);
        throw error;
    }
};


const encryptWithSymmetricKey = async (key, data) => {
    const encodedData = new TextEncoder().encode(data);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encodedData);
    return { encrypted, iv };
};

const decryptWithSymmetricKey = async (key, encryptedData, iv) => {
    return await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData);
};

const importPublicKey = async (base64Key) => {
    try {
        console.log("🔹 Importing Public Key (Base64):", base64Key);

        // Convert Base64 back to ArrayBuffer
        const binaryKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0)).buffer;

        const importedKey = await window.crypto.subtle.importKey(
            "spki",
            binaryKey,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );

        console.log("✅ Public Key Imported Successfully:", importedKey);
        return importedKey;
    } catch (error) {
        console.error("❌ Public Key Import Failed:", error);
        throw error;
    }
};

// פונקציה להמרת ArrayBuffer ל-Base64 (באופן תקני)
function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// פונקציה להמרת Base64 חזרה ל-ArrayBuffer (באופן תקני)
function base64ToArrayBuffer(base64) {
  console.log('base64ToArrayBuffer', base64);
    const binary = atob(base64);
    const length = binary.length;
    const buffer = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer.buffer;
}

// יצירת מפתח AES-GCM
async function generateKey() {
    return crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// הצפנה עם AES-GCM
async function encryptAES(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(JSON.stringify(data));

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encodedData
    );

    return {
        message: arrayBufferToBase64(encryptedBuffer),
        iv: arrayBufferToBase64(iv)
    };
}

// **שליחת הודעה עם 3 שכבות הצפנה**
async function createEncryptedMessage(clientId, message, key1, key2, key3) {
    // שכבה ראשונה
    const layer1 = await encryptAES(`${clientId}: ${message}`, key1);
    
    // שכבה שנייה
    const layer2 = await encryptAES(layer1, key2);
    
    // שכבה שלישית
    const layer3 = await encryptAES(layer2, key3);

    return layer3;
}

// **פענוח עם AES-GCM**
async function decryptAES(encryptedData, key) {
    const encryptedBuffer = base64ToArrayBuffer(encryptedData.message);
    const iv = base64ToArrayBuffer(encryptedData.iv);

    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encryptedBuffer
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedBuffer));
}

// **קבלת הודעה מוצפנת עם 3 שכבות ופענוח**
async function receiveEncryptedMessage(data, key1, key2, key3) {
    const receivedData = JSON.parse(data);

    // פענוח שכבה שלישית
    const layer2 = await decryptAES(receivedData, key3);

    // פענוח שכבה שנייה
    const layer1 = await decryptAES(layer2, key2);

    // פענוח שכבה ראשונה
    const originalMessage = await decryptAES(layer1, key1);

    console.log("Original Message:", originalMessage);
}

const App = () => {
    const [socket, setSocket] = useState(null);
    const [clients, setClients] = useState([]);
    const [clientId] = useState(generateUserName());
    const [message, setMessage] = useState("");
    const [selectedClient, setSelectedClient] = useState("");
    const [storedKeys, setStoredKeys] = useState({});
    const keysRef = useRef(null);
    const storedKeysRef = useRef({});  // Create a ref for storedKeys
    const [messages, setMessages] = useState([]);

    useEffect(() => {
        const ws = new WebSocket("wss://onion-chat-tzw8.onrender.com/");
        setSocket(ws);

        generateKeyPair().then((keyPair) => {
            keysRef.current = keyPair; // Store in ref instead of state
            ws.onopen = async () => {
                const exportedPublicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
                ws.send(JSON.stringify({
                    type: "register",
                    clientId,
                    publicKey: btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey))) // Send as Base64
                }));
            };
        });

        ws.onmessage = async (event) => {
            const data = JSON.parse(event.data);


    console.log("📩 Received WebSocket Message:", data);
    if (data.type === "relayMessage") {
        const { encryptedMessage, nextIndex, route, messageId } = data;
        console.log('encryptedMessage', encryptedMessage);

        // Decode the Base64 encrypted and iv values back to ArrayBuffer
        const encrypted = base64ToArrayBuffer(encryptedMessage.message);
        const iv = base64ToArrayBuffer(encryptedMessage.iv);
        console.log('encrypted', encrypted);
        console.log('iv', iv);
        console.log('messageId', messageId);
        console.table(storedKeysRef.current);
        const aesKey = storedKeysRef.current[messageId];
        if (aesKey) {
            console.log('aesKey', aesKey);

            const decrypted = await decryptWithSymmetricKey(
                aesKey, 
                encrypted,
                iv
            );

            console.log('decrypted', decrypted);
          try {
          const decryptedText = new TextDecoder().decode(decrypted);
        // Parse JSON string back to an object
            console.log('res', JSON.parse(decryptedText));

            if (nextIndex < route.length) {
                ws.send(JSON.stringify({
                    type: "sendMessage",
                    route,
                    encryptedMessage: JSON.parse(decryptedText),
                    messageId,
                    index: nextIndex
                }));
                setMessages(prev => [...prev, { sender: nextIndex < route.length ? 'unkown' : route[0].clientId, content: decryptedText }]);
            } else {
                setMessages(prev => [...prev, { sender: nextIndex < route.length ? 'unkown' : route[0].clientId, content: sanitizeMessage(decryptedText) }]);
            }
                    } catch (e) {
            console.error(e);
          }
        } else {
          console.log('No key for realy message')
        }
          
    }
        if (data.type === "clientList") {
        console.log("🔹 Raw Client List:", data.clients);

        try {
            const clientsWithKeys = await Promise.all(
                data.clients.map(async (client) => {
                    if (client.clientId !== clientId) {
                        console.log(`🔍 Processing Client ${client.clientId}:`, client.publicKey);
                        const importedKey = await importPublicKey(client.publicKey);
                        console.log(`✅ Imported Key for ${client.clientId}:`, importedKey);
                        return { clientId: client.clientId, publicKey: importedKey };
                    }
                    return null;
                })
            );

            setClients(clientsWithKeys.filter(Boolean));
            console.log("✅ Final Client List with Keys:", clientsWithKeys);
        } catch (error) {
            console.error("❌ Error Importing Public Keys:", error);
        }
    }

            if (data.type === "receiveEncryptedKey") {
                if (!keysRef.current) {
                    console.error("Private key not available yet");
                    return;
                }

                try {
                    // Decode Base64 before RSA decryption
                    const encryptedKeyArray = Uint8Array.from(atob(data.encryptedKey), c => c.charCodeAt(0));

                    const decryptedKeyBuffer = await window.crypto.subtle.decrypt(
                        { name: "RSA-OAEP" },
                        keysRef.current.privateKey,
                        encryptedKeyArray
                    );

                    // Validate AES key size (must be 32 bytes for AES-256)
                    if (decryptedKeyBuffer.byteLength !== 32) {
                        console.error("Decryption failed: Invalid AES key length", decryptedKeyBuffer.byteLength);
                        return;
                    }

                    const decryptedKey = await window.crypto.subtle.importKey(
                        "raw",
                        decryptedKeyBuffer,
                        { name: "AES-GCM" },
                        true,
                        ["encrypt", "decrypt"]
                    );

                    // Store the decrypted AES key in storedKeysRef
                    storedKeysRef.current[data.messageId] = decryptedKey;
                    console.log(`AES Key stored ${data.messageId}: `, decryptedKey);
                    setStoredKeys(prev => ({ ...prev, [data.messageId]: decryptedKey }));
                } catch (error) {
                    console.error("Decryption failed:", error);
                }
            }
        };

      
        return () => ws.close();
    }, []);

    const sendMessage = async () => {
        if (!selectedClient || !message) return;
        const possibleRelays = clients.filter(c => c.clientId !== selectedClient.clientId);
        if (possibleRelays.length < 2) return;

        const shuffled = [...possibleRelays].sort(() => 0.5 - Math.random());
        const route = [shuffled[0], shuffled[1], selectedClient];

        const symmetricKeys = await Promise.all(route.map(() => generateSymmetricKey()));
        const encryptedKeys = await Promise.all(route.map(async (relay, index) => {
            return btoa(String.fromCharCode(...new Uint8Array(await encryptWithPublicKey(relay.publicKey, symmetricKeys[index]))));
        }));

        const messageId = Math.random().toString(36).substr(2, 9);
        socket.send(JSON.stringify({
            type: "sendEncryptedKeys",
            messageId,
            recipients: route.map((client, index) => ({ clientId: client.clientId, encryptedKey: encryptedKeys[index] }))
        }));


        const theMessage = await createEncryptedMessage(clientId, message, symmetricKeys[2], symmetricKeys[1], symmetricKeys[0]);
        setTimeout(() => {
        socket.send(JSON.stringify({
            type: "sendMessage",
            route,
            encryptedMessage: theMessage,
            messageId
        }));
        },1000);
        setMessage("");
    };

    return (
       <div className="container">
            <h1 className="title">Secure Chat App</h1>
            <h2> Welcome {clientId} </h2>
            <div className="chat-box">
                <div className="messages">
                    {messages.map((msg, index) => (
                        <div key={index} className={`message ${msg.sender === "You" ? "sent" : "received"}`}>
                            {msg.content}
                        </div>
                    ))}
                </div>
                <div className="input-area">
                <select value={message} onChange={(e) => setMessage(e.target.value)}>
                        <option value="">Select Message</option>
                        {predefinedMessages.map((msg, index) => (
                            <option key={index} value={msg}>{msg}</option>
                        ))}
                    </select>
            {/* <input type="text" value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Enter message" /> */}
            <select onChange={(e) => {
                const selectedClientId = e.target.value;
                const client = clients.find(client => client.clientId === selectedClientId);
                setSelectedClient(client);
            }}>
                <option value="">Select recipient</option>
                {clients.map(client => (
                    <option key={client.clientId} value={client.clientId}>
                        {client.clientId}
                    </option>
                ))}
            </select>

                    <button onClick={sendMessage} className="send-button">Send</button>
                </div>
            </div>
        </div>
    );
};

export default App;
