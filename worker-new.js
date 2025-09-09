/**
 * Optimized Cloudflare Worker - Efficient caching with rate limiting and progress tracking
 * Supports up to 5 users with unlimited friends, smart caching, and deep search mode
 * Now with Firestore integration for persistent caching and audit logging
 */

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
};

// Updated limits based on your requirements
const LIMITS = {
    MAX_USERS_PER_REQUEST: 10,        // Up to 5 users as requested
    MAX_FRIENDS_UNLIMITED: true,     // No friend limit
    REQUESTS_PER_MINUTE: 100,        // 100 requests per minute target
    MAX_REQUESTS_PER_MINUTE: 120,    // 120 max as requested
    REQUEST_DELAY: 600,              // 600ms delay = 100 requests/minute
    CACHE_DURATION_HOURS: 6,         // 6 hour cache as requested
    DEEP_SEARCH_CACHE_UNLIMITED: true, // Deep search uses any cache age
    BATCH_SIZE: 50,                  // Batch size for user details/avatars
    MAX_TOTAL_SUBREQUESTS: 45        // Conservative subrequest limit
};

// Firestore cache durations
const FIRESTORE_CACHE_DURATIONS = {
    USER_DETAILS: 24 * 60 * 60 * 1000,     // 24 hours
    FRIENDS_LIST: 6 * 60 * 60 * 1000,      // 6 hours
    USER_LOOKUP: 24 * 60 * 60 * 1000,      // 24 hours
    STAFF_ROLES: 6 * 60 * 60 * 1000,       // 6 hours
    AVATARS: 7 * 24 * 60 * 60 * 1000,      // 7 days
};

function withCorsHeaders(response) {
    const headers = new Headers(response.headers);
    Object.entries(CORS_HEADERS).forEach(([key, value]) => {
        headers.set(key, value);
    });
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: headers
    });
}

// Simple rate limiting
const rateLimitStore = new Map();

async function applyRateLimit(request) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown-ip';
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - 60;

    if (!rateLimitStore.has(ip)) {
        rateLimitStore.set(ip, { timestamps: [] });
    }

    const ipData = rateLimitStore.get(ip);
    ipData.timestamps = ipData.timestamps.filter(timestamp => timestamp > windowStart);

    if (ipData.timestamps.length >= 30) { // 30 requests per minute
        return new Response(
            JSON.stringify({
                success: false,
                error: 'Rate limit exceeded. Please try again later.'
            }),
            { status: 429, headers: { 'Content-Type': 'application/json' } }
        );
    }

    ipData.timestamps.push(now);
    return null;
}

// --- Firebase Firestore REST API Client ---
class Firestore {
    constructor(projectId, serviceAccount) {
        this.projectId = projectId;
        this.serviceAccount = serviceAccount;
        this.token = null;
        this.tokenExpires = 0;
        this.baseUrl = `https://firestore.googleapis.com/v1/projects/${this.projectId}/databases/(default)/documents`;
    }

    async getAuthToken() {
        if (Date.now() < this.tokenExpires) {
            return this.token;
        }

        const header = { alg: 'RS256', typ: 'JWT' };
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iss: this.serviceAccount.client_email,
            sub: this.serviceAccount.client_email,
            aud: 'https://oauth2.googleapis.com/token',
            iat: now,
            exp: now + 3600,
            scope: 'https://www.googleapis.com/auth/datastore'
        };

        const encodedHeader = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const encodedPayload = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const dataToSign = `${encodedHeader}.${encodedPayload}`;

        const key = await crypto.subtle.importKey(
            'pkcs8',
             this.pemToBuffer(this.serviceAccount.private_key),
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, this.strToBuffer(dataToSign));
        const encodedSignature = this.bufferToBase64Url(signature);

        const jwt = `${dataToSign}.${encodedSignature}`;

        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
        });

        const tokenData = await tokenResponse.json();
        this.token = tokenData.access_token;
        this.tokenExpires = Date.now() + (tokenData.expires_in * 1000) - 60000; // Refresh 1 min before expiry
        return this.token;
    }

    async batchGetDocuments(paths) {
        if (paths.length === 0) return [];
        const token = await this.getAuthToken();
        const url = `${this.baseUrl}:batchGet`;
        const fullPaths = paths.map(path => `projects/${this.projectId}/databases/(default)/documents/${path}`);
        
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ documents: fullPaths })
        });

        if (!response.ok) throw new Error(`Firestore batchGet failed: ${response.status}`);
        return await response.json();
    }
    
    createWriteOperation(path, data) {
        return {
            update: {
                name: `projects/${this.projectId}/databases/(default)/documents/${path}`,
                fields: {
                    data: { stringValue: JSON.stringify(data) },
                    lastUpdated: { timestampValue: new Date().toISOString() }
                }
            }
        };
    }
    
    createLogOperation(basePath, logTimestamp, oldData, originalTimestamp) {
        return {
             update: {
                name: `projects/${this.projectId}/databases/(default)/documents/${basePath}/logs/${logTimestamp}`,
                fields: {
                    data: { stringValue: JSON.stringify(oldData) },
                    originalTimestamp: { timestampValue: originalTimestamp || new Date().toISOString() }
                }
            }
        };
    }

    async batchWriteDocuments(writes) {
        if (writes.length === 0) return;
        const token = await this.getAuthToken();
        const url = `${this.baseUrl}:commit`;
        
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ writes })
        });
        
        if (!response.ok) {
            const errorBody = await response.text();
            console.error("Firestore batchWrite error:", errorBody);
            throw new Error(`Firestore batchWrite failed: ${response.status}`);
        }
    }

    async createDocument(path, data) {
        const token = await this.getAuthToken();
        const url = `${this.baseUrl}/${path}`;
        
        const response = await fetch(url, {
            method: 'PATCH',
            headers: { 
                'Authorization': `Bearer ${token}`, 
                'Content-Type': 'application/json',
                'X-HTTP-Method-Override': 'PATCH'
            },
            body: JSON.stringify({
                fields: data.fields,
                updateMask: { fieldPaths: Object.keys(data.fields) }
            })
        });
        
        if (!response.ok) {
            const errorBody = await response.text();
            console.error("Firestore createDocument error:", errorBody);
            throw new Error(`Firestore createDocument failed: ${response.status}`);
        }
        
        return await response.json();
    }
    
    async getDocument(path) {
        const token = await this.getAuthToken();
        const url = `${this.baseUrl}/${path}`;
        
        const response = await fetch(url, {
            method: 'GET',
            headers: { 
                'Authorization': `Bearer ${token}`, 
                'Content-Type': 'application/json' 
            }
        });
        
        if (!response.ok) {
            if (response.status === 404) {
                return null;
            }
            const errorBody = await response.text();
            console.error("Firestore getDocument error:", errorBody);
            throw new Error(`Firestore getDocument failed: ${response.status}`);
        }
        
        return await response.json();
    }
    
    formatFirestoreResponse(response) {
        if (!response.fields || !response.fields.data) return null;
        try {
            return {
                data: JSON.parse(response.fields.data.stringValue),
                lastUpdated: response.fields.lastUpdated.timestampValue
            };
        } catch (e) {
            return null;
        }
    }
    
    pemToBuffer(pem) {
        const base64 = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, '');
        const binaryString = atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    strToBuffer(str) {
        return new TextEncoder().encode(str);
    }
    
    bufferToBase64Url(buffer) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
}

// Subrequest counter to stay within limits
class SubrequestManager {
    constructor() {
        this.count = 0;
        this.maxRequests = LIMITS.MAX_TOTAL_SUBREQUESTS;
    }

    reset() {
        this.count = 0;
    }

    canMakeRequest() {
        return this.count < this.maxRequests;
    }

    async makeRequest(url, options = {}, retryCount = 0) {
        if (!this.canMakeRequest()) {
            throw new Error(`Request limit reached (${this.count}/${this.maxRequests}). Please try with fewer users.`);
        }

        this.count++;
        console.log(`Making subrequest ${this.count}/${this.maxRequests} to ${url}`);

        try {
            const response = await fetch(url, {
                ...options,
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'Saikou-Tools/1.0',
                    ...options.headers
                }
            });

            // Handle 429 rate limiting
            if (response.status === 429) {
                const retryAfter = parseInt(response.headers.get('Retry-After') || '60', 10);

                if (retryCount < 3) { // Max 3 retries
                    console.log(`Rate limited (429), retrying after ${retryAfter}s (attempt ${retryCount + 1}/3)`);

                    if (options.onRateLimit) {
                        options.onRateLimit(`Rate limited - waiting ${retryAfter}s (retry ${retryCount + 1}/3)`);
                    }

                    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
                    this.count--;
                    return await this.makeRequest(url, options, retryCount + 1);
                } else {
                    throw new Error(`Rate limited after 3 retries: HTTP 429`);
                }
            }

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`Request failed for ${url}:`, error);
            throw error;
        }
    }

    getUsage() {
        return {
            used: this.count,
            max: this.maxRequests,
            remaining: this.maxRequests - this.count
        };
    }
}

const subrequestManager = new SubrequestManager();

// Hybrid cache implementation (Firestore + in-memory fallback)
class HybridCache {
    constructor(firestore) {
        this.firestore = firestore;
        this.memoryCache = new Map();
        this.maxMemorySize = 500; // Smaller memory cache since we have Firestore
    }

    async get(key, maxAgeMs = LIMITS.CACHE_DURATION_HOURS * 60 * 60 * 1000, useDeepSearch = false) {
        // For deep search, check Firestore for any cached data regardless of age
        if (useDeepSearch) {
            try {
                const doc = await this.firestore.getDocument(`cache/${key.replace(/[^a-zA-Z0-9]/g, '_')}`);
                if (doc) {
                    const cacheData = this.firestore.formatFirestoreResponse(doc);
                    if (cacheData && cacheData.data) {
                        console.log(`Firestore deep search hit for: ${key}`);
                        return cacheData.data;
                    }
                }
            } catch (error) {
                console.warn(`Firestore deep search failed for ${key}:`, error.message);
            }
            return null;
        }

        // Normal cache logic - check memory first, then Firestore
        const memoryItem = this.memoryCache.get(key);
        if (memoryItem && !this._isExpired(memoryItem, maxAgeMs)) {
            // Validate cache completeness for user data
            if (this._isCacheDataComplete(key, memoryItem.data)) {
                console.log(`Memory cache hit for: ${key}`);
                return memoryItem.data;
            } else {
                console.log(`Memory cache incomplete for: ${key}, removing`);
                this.memoryCache.delete(key);
            }
        }

        // Check Firestore
        try {
            const doc = await this.firestore.getDocument(`cache/${key.replace(/[^a-zA-Z0-9]/g, '_')}`);
            if (doc) {
                const cacheData = this.firestore.formatFirestoreResponse(doc);
                if (cacheData && !this._isFirestoreExpired(cacheData, maxAgeMs)) {
                    // Validate cache completeness
                    if (this._isCacheDataComplete(key, cacheData.data)) {
                        // Store in memory cache for faster future access
                        this.memoryCache.set(key, {
                            data: cacheData.data,
                            timestamp: new Date(cacheData.lastUpdated).getTime()
                        });
                        console.log(`Firestore cache hit for: ${key}`);
                        return cacheData.data;
                    } else {
                        console.log(`Firestore cache incomplete for: ${key}, treating as miss`);
                    }
                }
            }
        } catch (error) {
            console.warn(`Firestore cache failed for ${key}:`, error.message);
        }

        return null;
    }

    _isCacheDataComplete(key, data) {
        // Check if user detail cache has avatar data
        if (key.startsWith('userdetails:') || key.startsWith('user:')) {
            if (!data) return false;
            // User data should have an avatarUrl field, and it shouldn't be just a placeholder
            if (!data.avatarUrl) {
                console.log(`Cache data missing avatarUrl for key: ${key}`);
                return false;
            }
            // Check if it's just a placeholder (question mark image)
            if (data.avatarUrl.includes('text=?') || data.avatarUrl.includes('text=%3F') || 
                data.avatarUrl.includes('placehold.co')) {
                console.log(`Cache data has placeholder avatar for key: ${key}`);
                return false;
            }
            // Additional check: make sure it's actually a valid Roblox avatar URL or reasonable image URL
            if (!data.avatarUrl.includes('rbxcdn.com') && !data.avatarUrl.includes('roblox.com') && 
                !data.avatarUrl.startsWith('https://') && !data.avatarUrl.startsWith('http://')) {
                console.log(`Cache data has invalid avatar URL for key: ${key}`);
                return false;
            }
        }
        
        // Check if friend data has required fields
        if (key.startsWith('friends:')) {
            if (!Array.isArray(data)) return false;
        }
        
        return true;
    }

    async set(key, data, documentsToWrite = null) {
        const timestamp = Date.now();
        
        // Always store in memory cache
        if (this.memoryCache.size >= this.maxMemorySize) {
            const firstKey = this.memoryCache.keys().next().value;
            this.memoryCache.delete(firstKey);
        }

        this.memoryCache.set(key, {
            data,
            timestamp
        });

        // Store in Firestore (batch operation if documentsToWrite provided)
        const firestoreKey = key.replace(/[^a-zA-Z0-9]/g, '_');
        const writeOperation = this.firestore.createWriteOperation(`cache/${firestoreKey}`, data);

        if (documentsToWrite) {
            documentsToWrite.push(writeOperation);
        } else {
            try {
                await this.firestore.batchWriteDocuments([writeOperation]);
            } catch (error) {
                console.warn(`Failed to write to Firestore cache for ${key}:`, error.message);
            }
        }
    }

    _isExpired(item, maxAgeMs) {
        return Date.now() - item.timestamp > maxAgeMs;
    }

    _isFirestoreExpired(cacheData, maxAgeMs) {
        return Date.now() - new Date(cacheData.lastUpdated).getTime() > maxAgeMs;
    }

    getStats() {
        return {
            memorySize: this.memoryCache.size,
            maxMemorySize: this.maxMemorySize
        };
    }
}

// Staff role checking - more efficient than individual calls
const STAFF_ROLES = [
    'Lead Developer',
    'Community Manager',
    'Head Moderator',
    'Moderator',
    'Trial Moderator',
    'Contractor',
    'Trial Contractor'
];

const ROLE_COLORS = {
    'Lead Developer': '#e5a230',
    'Community Manager': '#68ce3e',
    'Head Moderator': '#D206E5',
    'Senior Moderator': '#8D75FF',
    'Moderator': '#9b59b6',
    'Trial Moderator': '#71368a',
    'Contractor': '#05b845',
    'Trial Contractor': '#1f8b4c'
};

async function getStaffMap(groupId = 3149674, firestore, cache) {
    const cacheKey = `staff_roles_${groupId}`;
    
    // Check cache first
    const cached = await cache.get(cacheKey, FIRESTORE_CACHE_DURATIONS.STAFF_ROLES);
    if (cached) {
        console.log(`Using cached staff data`);
        return new Map(Object.entries(cached).map(([id, role]) => [parseInt(id, 10), role]));
    }

    console.log('Building staff cache...');
    const staffMap = new Map();

    try {
        const rolesResponse = await subrequestManager.makeRequest(`https://groups.roblox.com/v1/groups/${groupId}/roles`);
        const targetRoles = rolesResponse.roles.filter(role => STAFF_ROLES.includes(role.name));
        console.log(`Found ${targetRoles.length} target staff roles:`, targetRoles.map(r => r.name));

        for (const role of targetRoles) {
            if (!subrequestManager.canMakeRequest()) {
                console.warn('Subrequest limit reached while building staff cache');
                break;
            }

            let nextPageCursor = null;
            let pageCount = 0;

            do {
                if (!subrequestManager.canMakeRequest()) break;

                const url = `https://groups.roblox.com/v1/groups/${groupId}/roles/${role.id}/users?limit=100&sortOrder=Asc${nextPageCursor ? `&cursor=${nextPageCursor}` : ''}`;

                try {
                    const membersResponse = await subrequestManager.makeRequest(url);
                    if (membersResponse.data) {
                        for (const member of membersResponse.data) {
                            staffMap.set(member.userId, role.name);
                        }
                        console.log(`Cached ${membersResponse.data.length} ${role.name} members`);
                    }
                    nextPageCursor = membersResponse.nextPageCursor;
                    pageCount++;

                    if (pageCount >= 5) {
                        console.warn(`Limiting ${role.name} to 5 pages to save subrequests`);
                        break;
                    }
                } catch (error) {
                    console.error(`Error fetching ${role.name} members:`, error);
                    break;
                }
            } while (nextPageCursor);
        }

        const staffObject = Object.fromEntries(staffMap);
        await cache.set(cacheKey, staffObject);
        console.log(`Staff cache built with ${staffMap.size} staff members`);
        return staffMap;

    } catch (error) {
        console.error("Failed to build staff cache:", error);
        return new Map();
    }
}
// Individual user role check for lookup feature
async function getUserGroupRole(userId, groupId = 3149674) {
    try {
        if (!subrequestManager.canMakeRequest()) {
            console.warn('Subrequest limit reached, skipping individual role check');
            return null;
        }

        const response = await subrequestManager.makeRequest(`https://groups.roblox.com/v2/users/${userId}/groups/roles`);

        if (response.data) {
            const saikouGroup = response.data.find(g => g.group.id === groupId);
            if (saikouGroup) {
                const roleName = saikouGroup.role.name;

                if (STAFF_ROLES.includes(roleName)) {
                    console.log(`User ${userId} has staff role: ${roleName}`);
                    return {
                        groupRole: roleName,
                        groupRoleColor: ROLE_COLORS[roleName] || null
                    };
                } else {
                    console.log(`User ${userId} has role ${roleName}, but it's not a staff role`);
                }
            }
        }

        return null;
    } catch (error) {
        console.error(`Error checking individual group role for user ${userId}:`, error);
        return null;
    }
}

async function getUserByUsername(username, isDeepSearch = false, cache) {
    const cacheKey = `user:username:${username.toLowerCase()}`;
    const maxAge = isDeepSearch ? Infinity : FIRESTORE_CACHE_DURATIONS.USER_DETAILS;

    const cached = await cache.get(cacheKey, maxAge, isDeepSearch);
    if (cached) {
        console.log(`Cache hit for username: ${username}`);
        return cached;
    }

    if (isDeepSearch) {
        console.log(`Deep search: no cache for username ${username}, skipping API call`);
        return null;
    }

    try {
        const usernameResponse = await subrequestManager.makeRequest('https://users.roblox.com/v1/usernames/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usernames: [username] })
        });

        const partialUser = usernameResponse.data?.[0] || null;
        if (!partialUser) {
            return null;
        }

        const fullUser = await getUserById(partialUser.id, isDeepSearch, cache);

        if (fullUser) {
            await cache.set(cacheKey, fullUser);
        }

        return fullUser;
    } catch (error) {
        console.error(`Failed to get user ${username}:`, error);
        return null;
    }
}

async function getUserById(userId, isDeepSearch = false, cache) {
    const cacheKey = `user:id:${userId}`;
    const maxAge = isDeepSearch ? Infinity : FIRESTORE_CACHE_DURATIONS.USER_DETAILS;

    const cached = await cache.get(cacheKey, maxAge, isDeepSearch);
    if (cached) {
        console.log(`Cache hit for user ID: ${userId}`);
        return cached;
    }

    if (isDeepSearch) {
        console.log(`Deep search: no cache for user ID ${userId}, skipping API call`);
        return null;
    }

    try {
        // Fetch both user data and avatar in parallel
        const [userData, avatarData] = await Promise.all([
            subrequestManager.makeRequest(`https://users.roblox.com/v1/users/${userId}`),
            subrequestManager.makeRequest(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=150x150&format=Png&isCircular=false`)
        ]);
        
        if (userData) {
            // Add avatar URL to user data
            const avatarUrl = avatarData?.data?.[0]?.imageUrl || 'https://placehold.co/150x150/1f222c/FFFFFF?text=?';
            const completeUserData = {
                ...userData,
                avatarUrl: avatarUrl
            };
            
            await cache.set(cacheKey, completeUserData);
            if (userData.name) {
                await cache.set(`user:username:${userData.name.toLowerCase()}`, completeUserData);
            }
            
            return completeUserData;
        }
        return null;
    } catch (error) {
        console.error(`Failed to get user ${userId}:`, error);
        return null;
    }
}

async function getUserFriends(userId, isDeepSearch = false, cache) {
    const cacheKey = `friends:${userId}`;
    const maxAge = isDeepSearch ? Infinity : FIRESTORE_CACHE_DURATIONS.FRIENDS_LIST;

    const cached = await cache.get(cacheKey, maxAge, isDeepSearch);
    if (cached) {
        console.log(`Cache hit for friends of user: ${userId}`);
        return cached;
    }

    if (isDeepSearch) {
        console.log(`Deep search: no cache for friends of ${userId}, skipping API call`);
        return [];
    }

    try {
        const data = await subrequestManager.makeRequest(`https://friends.roblox.com/v1/users/${userId}/friends`);
        const friends = data.data || [];

        await cache.set(cacheKey, friends);
        return friends;
    } catch (error) {
        console.error(`Failed to get friends for ${userId}:`, error);
        return [];
    }
}

async function getBatchUserDetails(userIds, isDeepSearch = false, onProgress = null, cache, documentsToWrite = []) {
    const results = new Map();
    const uncachedIds = [];
    const maxAge = isDeepSearch ? Infinity : FIRESTORE_CACHE_DURATIONS.USER_DETAILS;

    // Check cache for each user
    for (const id of userIds) {
        const cacheKey = `userdetails:${id}`;
        const cached = await cache.get(cacheKey, maxAge, isDeepSearch);

        if (cached) {
            results.set(id, cached);
        } else if (!isDeepSearch) {
            uncachedIds.push(id);
        }
    }

    console.log(`User details: ${results.size} cached, ${uncachedIds.length} need fetching`);

    if (uncachedIds.length === 0 || isDeepSearch) {
        return results;
    }

    // Process uncached IDs in batches
    for (let i = 0; i < uncachedIds.length; i += LIMITS.BATCH_SIZE) {
        if (!subrequestManager.canMakeRequest()) {
            console.warn('Subrequest limit reached, stopping user detail fetch');
            break;
        }

        const batch = uncachedIds.slice(i, i + LIMITS.BATCH_SIZE);

        if (onProgress) {
            const progress = Math.round(((i + batch.length) / uncachedIds.length) * 100);
            onProgress(`Fetching user details... ${i + batch.length}/${uncachedIds.length}`, progress);
        }

        try {
            const data = await subrequestManager.makeRequest('https://users.roblox.com/v1/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userIds: batch }),
                onRateLimit: (message) => {
                    if (onProgress) {
                        onProgress(`Rate limited: ${message}`, progress);
                    }
                }
            });

            data.data?.forEach(user => {
                results.set(user.id, user);
                // Add to batch write operations
                const cacheKey = `userdetails:${user.id}`;
                cache.set(cacheKey, user, documentsToWrite);
            });
        } catch (error) {
            console.error(`Failed to get batch user details:`, error);
        }

        if (i + LIMITS.BATCH_SIZE < uncachedIds.length) {
            await new Promise(resolve => setTimeout(resolve, LIMITS.REQUEST_DELAY));
        }
    }

    return results;
}

async function getBatchAvatars(userIds, isDeepSearch = false, onProgress = null, cache, documentsToWrite = []) {
    const results = new Map();
    const uncachedIds = [];
    const maxAge = isDeepSearch ? Infinity : FIRESTORE_CACHE_DURATIONS.AVATARS;

    // Check cache for each avatar
    for (const id of userIds) {
        const cacheKey = `avatar:${id}`;
        const cached = await cache.get(cacheKey, maxAge, isDeepSearch);

        if (cached) {
            results.set(id, cached);
        } else if (!isDeepSearch) {
            uncachedIds.push(id);
        } else {
            results.set(id, 'https://placehold.co/150x150/1f222c/FFFFFF?text=?');
        }
    }

    console.log(`Avatars: ${results.size} cached, ${uncachedIds.length} need fetching`);

    if (uncachedIds.length === 0) {
        return results;
    }

    // Process in batches of 100 (Roblox API limit)
    for (let i = 0; i < uncachedIds.length; i += 100) {
        if (!subrequestManager.canMakeRequest()) {
            console.warn('Subrequest limit reached, stopping avatar fetch');
            break;
        }

        const batch = uncachedIds.slice(i, i + 100);

        if (onProgress) {
            const progress = Math.round(((i + batch.length) / uncachedIds.length) * 100);
            onProgress(`Fetching avatars... ${i + batch.length}/${uncachedIds.length}`, progress);
        }

        try {
            const data = await subrequestManager.makeRequest(
                `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${batch.join(',')}&size=150x150&format=Png&isCircular=false`,
                {
                    onRateLimit: (message) => {
                        if (onProgress) {
                            onProgress(`Rate limited: ${message}`, progress);
                        }
                    }
                }
            );

            data.data?.forEach(avatar => {
                const avatarUrl = avatar.imageUrl || 'https://placehold.co/150x150/1f222c/FFFFFF?text=?';
                results.set(avatar.targetId, avatarUrl);
                // Add to batch write operations
                const cacheKey = `avatar:${avatar.targetId}`;
                cache.set(cacheKey, avatarUrl, documentsToWrite);
            });
        } catch (error) {
            console.error(`Failed to get batch avatars:`, error);
            batch.forEach(id => {
                const placeholder = 'https://placehold.co/150x150/1f222c/FFFFFF?text=?';
                results.set(id, placeholder);
                const cacheKey = `avatar:${id}`;
                cache.set(cacheKey, placeholder, documentsToWrite);
            });
        }

        if (i + 100 < uncachedIds.length) {
            await new Promise(resolve => setTimeout(resolve, LIMITS.REQUEST_DELAY));
        }
    }

    return results;
}

async function handleBanList(env) {
    try {
        if (env.BAN_CACHE_WORKER_URL) {
            console.log('Using dedicated ban cache worker');
            const response = await fetch(env.BAN_CACHE_WORKER_URL);

            if (!response.ok) {
                throw new Error(`Ban cache worker error: ${response.status}`);
            }

            const data = await response.json();
            return data;
        }

        const banListUrls = [
            env.BAN_LIST_URL,
            'http://bans.saikouapi.xyz/v1/bans/list-bans?sortOrder=Desc',
            'https://saikou-banlist-proxy.saikoudevelopment.workers.dev',
            'https://saikou.banlist.workers.dev',
            'https://api.saikou.dev/v1/bans/list-bans'
        ].filter(Boolean);

        for (let i = 0; i < banListUrls.length; i++) {
            const banListUrl = banListUrls[i];
            const headers = {};

            if (env.SAIKOU_API_KEY) {
                headers['X-API-KEY'] = env.SAIKOU_API_KEY;
            } else if (env['X-API-KEY']) {
                headers['X-API-KEY'] = env['X-API-KEY'];
            }

            console.log(`Trying ban list URL ${i + 1}/${banListUrls.length}: ${banListUrl}`);

            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(banListUrl, {
                    headers,
                    signal: controller.signal
                });

                clearTimeout(timeoutId);
                console.log(`Response status: ${response.status}`);

                if (response.ok) {
                    const data = await response.json();
                    console.log(`SUCCESS with ${banListUrl} - data type: ${Array.isArray(data) ? 'array' : typeof data}, length: ${Array.isArray(data) ? data.length : 'N/A'}`);

                    const banList = Array.isArray(data) ? data : (data.data || data);
                    return { success: true, data: banList };
                } else {
                    console.warn(`Failed ${banListUrl}: HTTP ${response.status}`);
                }
            } catch (error) {
                console.warn(`Error with ${banListUrl}: ${error.message}`);
            }
        }

        console.warn('All ban list URLs failed, using emergency fallback');

        const emergencyBanList = [
            {
                "RobloxUsername": "TestBannedUser",
                "RobloxID": 1,
                "Moderator": "System",
                "Reason": "Emergency fallback test ban",
                "Date": new Date().toISOString(),
                "type": "permban"
            }
        ];

        return {
            success: true,
            data: emergencyBanList,
            warning: 'Using emergency fallback ban list - all APIs failed',
            fallback: true
        };
    } catch (error) {
        console.error('Ban list error:', error);
        console.error("Could not fetch Saikou ban list for graph:", error.message);
        return {
            success: true,
            data: [],
            warning: `Ban list unavailable: ${error.message}`,
            fallback: true
        };
    }
}

// Person of Interest Functions
async function getPersonOfInterestStatus(userId, firestore) {
    try {
        const doc = await firestore.getDocument(`poi/${userId}`);
        if (doc && doc.fields) {
            return {
                isPoi: true,
                markedBy: doc.fields.markedBy?.stringValue || 'Unknown',
                reason: doc.fields.reason?.stringValue || 'No reason provided',
                timestamp: doc.fields.timestamp?.timestampValue || new Date().toISOString()
            };
        }
    } catch (error) {
        console.error('Error fetching POI status:', error);
    }
    return { isPoi: false };
}

async function setPersonOfInterestStatus(userId, data, firestore) {
    const timestamp = new Date().toISOString();
    const poiData = {
        fields: {
            isPoi: { booleanValue: data.isPoi },
            markedBy: { stringValue: data.markedBy || 'Unknown' },
            reason: { stringValue: data.reason || '' },
            timestamp: { timestampValue: timestamp },
            userId: { integerValue: userId },
            username: { stringValue: data.username || '' }
        }
    };

    const auditLogData = {
        fields: {
            action: { stringValue: data.isPoi ? 'MARKED_POI' : 'UNMARKED_POI' },
            userId: { integerValue: userId },
            username: { stringValue: data.username || '' },
            markedBy: { stringValue: data.markedBy || 'Unknown' },
            reason: { stringValue: data.reason || '' },
            timestamp: { timestampValue: timestamp }
        }
    };

    try {
        await firestore.createDocument(`poi/${userId}`, poiData);
        await firestore.createDocument(`poi_logs/${userId}_${Date.now()}`, auditLogData);
        return { success: true };
    } catch (error) {
        console.error('Error updating POI status:', error);
        return { success: false, error: error.message };
    }
}

async function handleUserLookup(query, env, firestore, cache) {
    subrequestManager.reset();

    try {
        let user;
        if (isNaN(query)) {
            user = await getUserByUsername(query, false, cache);
        } else {
            user = await getUserById(parseInt(query), false, cache);
        }

        if (!user) {
            return { success: false, error: 'User not found' };
        }

        const documentsToWrite = [];

        // Get friends
        const friends = await getUserFriends(user.id, false, cache);

        // Get avatar
        const avatarMap = await getBatchAvatars([user.id], false, null, cache, documentsToWrite);
        user.avatarUrl = avatarMap.get(user.id);

        // Get friend avatars (limited batch for performance)
        const friendIds = friends.slice(0, 50).map(f => f.id);
        const friendAvatars = await getBatchAvatars(friendIds, false, null, cache, documentsToWrite);
        friends.forEach(friend => {
            if (friendAvatars.has(friend.id)) {
                friend.avatarUrl = friendAvatars.get(friend.id);
            }
        });

        // Get ban list
        const banList = await handleBanList(env);
        const banMap = new Map();
        if (banList.success && banList.data) {
            banList.data.forEach(ban => banMap.set(ban.userId || ban.RobloxID, ban));
        }

        const userBan = banMap.get(user.id);
        const bannedFriends = friends.filter(friend => banMap.has(friend.id));

        // Check group role
        const roleInfo = await getUserGroupRole(user.id, 3149674);

        // Check POI status
        const poiStatus = await getPersonOfInterestStatus(user.id, firestore);

        // Risk assessment
        const accountAgeMs = Date.now() - new Date(user.created).getTime();
        const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;
        const isNewAccount = accountAgeMs < ninetyDaysMs;
        const friendCount = friends.length;
        const isPotentialRisk = isNewAccount && friendCount < 50;

        const result = {
            success: true,
            profile: {
                ...user,
                isBanned: !!userBan,
                banInfo: userBan,
                friendCount: friendCount,
                groupRole: roleInfo?.groupRole || null,
                groupRoleColor: roleInfo?.groupRoleColor || null,
                isPotentialRisk: isPotentialRisk,
                isPOI: poiStatus.isPoi,
                poiData: poiStatus.isPoi ? poiStatus : undefined
            },
            friends: friends,
            bannedFriends: bannedFriends.map(friend => ({
                ...friend,
                banInfo: banMap.get(friend.id)
            })),
            banHistory: banMap.has(user.id) ? [banMap.get(user.id)] : []
        };

        // Cache the lookup result
        const lookupCacheKey = `lookup:${user.id}`;
        await cache.set(lookupCacheKey, result, documentsToWrite);

        // Write all cache updates to Firestore
        if (documentsToWrite.length > 0) {
            try {
                await firestore.batchWriteDocuments(documentsToWrite);
            } catch (error) {
                console.warn('Failed to write cache updates to Firestore:', error.message);
            }
        }

        return result;

    } catch (error) {
        console.error('Lookup error:', error);
        return { success: false, error: error.message };
    }
}

async function handleFriendGraph(usersQuery, env, isDeepSearch = false) {
    subrequestManager.reset();

    // Initialize Firestore if available
    let firestore = null;
    let cache = null;

    try {
        if (env.FIREBASE_PROJECT_ID && env.FIREBASE_SERVICE_ACCOUNT) {
            const FIREBASE_PROJECT_ID = env.FIREBASE_PROJECT_ID;
            const FIREBASE_SERVICE_ACCOUNT = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
            firestore = new Firestore(FIREBASE_PROJECT_ID, FIREBASE_SERVICE_ACCOUNT);
            cache = new HybridCache(firestore);
        }
    } catch (error) {
        console.warn('Failed to initialize Firestore, using memory-only cache:', error.message);
    }

    // Fallback to simple cache if Firestore unavailable
    if (!cache) {
        const SimpleCache = class {
            constructor() { this.cache = new Map(); this.maxSize = 1000; }
            async get(key, maxAge, useDeepSearch = false) {
                const item = this.cache.get(key);
                if (!item) return null;
                if (useDeepSearch) return item.data;
                if (Date.now() - item.timestamp > maxAge) { this.cache.delete(key); return null; }
                return item.data;
            }
            async set(key, data) {
                if (this.cache.size >= this.maxSize) {
                    const firstKey = this.cache.keys().next().value;
                    this.cache.delete(firstKey);
                }
                this.cache.set(key, { data, timestamp: Date.now() });
            }
            getStats() { return { memorySize: this.cache.size, maxMemorySize: this.maxSize }; }
        };
        cache = new SimpleCache();
    }

    const usernames = usersQuery.split(',').map(u => u.trim()).slice(0, LIMITS.MAX_USERS_PER_REQUEST);

    if (usernames.length > LIMITS.MAX_USERS_PER_REQUEST) {
        return {
            success: false,
            error: `Too many users requested. Maximum ${LIMITS.MAX_USERS_PER_REQUEST} users allowed per request.`
        };
    }

    const progressSteps = [];
    const addProgress = (message, progress = 0) => {
        progressSteps.push({ message, progress, timestamp: Date.now() });
        console.log(`Progress: ${message} (${progress}%)`);
    };

    const documentsToWrite = [];

    try {
        addProgress('Resolving initial users...', 5);

        // Step 1: Get initial users
        const initialUsers = [];
        for (let i = 0; i < usernames.length; i++) {
            const username = usernames[i];
            const user = isNaN(username) ?
                await getUserByUsername(username, isDeepSearch, cache) :
                await getUserById(parseInt(username), isDeepSearch, cache);

            if (user) {
                initialUsers.push(user);
            }

            addProgress(`Resolved ${i + 1}/${usernames.length} users`, 5 + (i + 1) / usernames.length * 10);
        }

        if (initialUsers.length === 0) {
            return {
                success: false,
                error: isDeepSearch ? 'No cached users found for deep search' : 'No valid users found',
                progressSteps
            };
        }
        
        const nodes = new Map();
        const links = new Set();
        
        initialUsers.forEach(user => {
            nodes.set(user.id, {
                id: user.id,
                name: user.name,
                displayName: user.displayName || user.name,
                isSeedUser: true
            });
        });

        if (isDeepSearch) {
            addProgress('Starting deep cache search...', 20);
            const queue = [...initialUsers.map(u => u.id)];
            const processed = new Set();
            const maxNodes = 500;

            while(queue.length > 0 && nodes.size < maxNodes) {
                const currentUserId = queue.shift();
                if (processed.has(currentUserId)) continue;
                processed.add(currentUserId);

                const friends = await getUserFriends(currentUserId, true, cache);
                
                if (!nodes.has(currentUserId)) {
                     const userDetails = await getUserById(currentUserId, true, cache);
                     if (userDetails) {
                         nodes.set(currentUserId, {
                            id: userDetails.id,
                            name: userDetails.name,
                            displayName: userDetails.displayName || userDetails.name
                        });
                     } else {
                         continue;
                     }
                }
                
                addProgress(`Processing cached friends for ${nodes.get(currentUserId).name || 'user'}...`, 20 + Math.round((processed.size / (processed.size + queue.length)) * 30));

                for (const friend of friends) {
                    const linkTuple = JSON.stringify({ source: currentUserId, target: friend.id });
                    links.add(linkTuple);

                    if (!processed.has(friend.id) && !queue.includes(friend.id) && nodes.size < maxNodes) {
                         if (!nodes.has(friend.id)) {
                             nodes.set(friend.id, {
                                id: friend.id,
                                name: friend.name,
                                displayName: friend.displayName || friend.name
                            });
                         }
                        queue.push(friend.id);
                    }
                }
            }
        } else {
            addProgress('Fetching friend lists...', 15);
            const friendResults = [];
            for (let i = 0; i < initialUsers.length; i++) {
                const user = initialUsers[i];
                addProgress(`Fetching friends for ${user.name}... (${i + 1}/${initialUsers.length})`, 15 + (i / initialUsers.length) * 25);
                const friends = await getUserFriends(user.id, isDeepSearch, cache);
                friendResults.push({ userId: user.id, friends });
                if (i < initialUsers.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, LIMITS.REQUEST_DELAY));
                }
            }
            friendResults.forEach(({ userId, friends }) => {
                friends.forEach(friend => {
                    if (!nodes.has(friend.id)) {
                        nodes.set(friend.id, {
                            id: friend.id,
                            name: friend.name,
                            displayName: friend.displayName || friend.name
                        });
                    }
                    links.add(JSON.stringify({ source: userId, target: friend.id }));
                });
            });
        }

        addProgress('Processing user details...', 50);

        const allUserIds = Array.from(nodes.keys());

        const userDetails = await getBatchUserDetails(allUserIds, isDeepSearch, (message, progress) => {
            addProgress(`User details: ${message}`, 50 + progress * 0.2);
        }, cache, documentsToWrite);

        addProgress('Processing avatars...', 70);

        const avatars = await getBatchAvatars(allUserIds, isDeepSearch, (message, progress) => {
            addProgress(`Avatars: ${message}`, 70 + progress * 0.15);
        }, cache, documentsToWrite);

        addProgress('Loading staff cache...', 80);
        const staffRoleMap = await getStaffMap(3149674, firestore, cache);

        addProgress('Fetching ban list...', 85);
        const banList = await handleBanList(env);
        
        addProgress('Fetching POI list...', 88);
        const poiStatuses = new Map();
        if (firestore) {
            try {
                for (const userId of allUserIds) {
                    const poiStatus = await getPersonOfInterestStatus(userId, firestore);
                    if (poiStatus.isPoi) {
                        poiStatuses.set(userId, poiStatus);
                    }
                }
            } catch (error) {
                console.warn('Failed to fetch POI statuses:', error.message);
            }
        }

        // Update nodes with details and avatars
        for (const [userId, node] of nodes.entries()) {
            const details = userDetails.get(userId);
            if (details) {
                Object.assign(node, {
                    name: details.name || node.name,
                    displayName: details.displayName || details.name || node.displayName,
                    created: details.created,
                    friendCount: details.friendCount,
                });
            }

            // Always set avatar URL from the avatars map
            node.avatarUrl = avatars.get(userId) || 'https://placehold.co/150x150/1f222c/FFFFFF?text=?';

            if (staffRoleMap.has(userId)) {
                node.groupRole = staffRoleMap.get(userId);
                node.groupRoleColor = ROLE_COLORS[staffRoleMap.get(userId)] || null;
            }

            if (node.created) {
                const accountAge = Date.now() - new Date(node.created).getTime();
                const ninetyDays = 90 * 24 * 60 * 60 * 1000;
                node.isNewAccount = accountAge < ninetyDays;
            }
            
            if (poiStatuses.has(userId)) {
                node.isPOI = true;
                node.poiData = poiStatuses.get(userId);
            }
        }

        // Apply ban status
        if (banList.success && banList.data) {
            const banMap = new Map();
            banList.data.forEach(ban => {
                const userId = ban.RobloxID || ban.userId || ban.id;
                const reason = ban.Reason || ban.reason || 'No reason provided.';
                banMap.set(userId, reason);
            });

            nodes.forEach((node, userId) => {
                if (banMap.has(userId)) {
                    node.isBanned = true;
                    node.banReason = banMap.get(userId);
                }
            });
        }

        const finalLinks = Array.from(links)
            .map(link => {
                try {
                    return JSON.parse(link);
                } catch (e) {
                    return null;
                }
            })
            .filter(link => link && nodes.has(link.source) && nodes.has(link.target));

        addProgress('Finalizing graph...', 95);

        // Write all cache updates to Firestore
        if (documentsToWrite.length > 0 && firestore) {
            try {
                await firestore.batchWriteDocuments(documentsToWrite);
                console.log(`Wrote ${documentsToWrite.length} cache updates to Firestore`);
            } catch (error) {
                console.warn('Failed to write cache updates to Firestore:', error.message);
            }
        }

        const usage = subrequestManager.getUsage();
        const cacheStats = cache.getStats();

        addProgress('Graph generation complete!', 100);

        return {
            success: true,
            nodes: Array.from(nodes.values()),
            links: finalLinks,
            isDeepSearch,
            progressSteps,
            stats: {
                nodeCount: nodes.size,
                linkCount: finalLinks.length,
                subrequestsUsed: usage.used,
                subrequestsRemaining: usage.remaining,
                cacheHits: cacheStats.memorySize || 0,
                limitInfo: `Used ${usage.used}/${usage.max} subrequests`,
                processingMode: isDeepSearch ? 'Deep Search (Cache Only)' : 'Normal (API + Cache)',
                firestoreEnabled: !!firestore
            }
        };

    } catch (error) {
        console.error('Graph generation error:', error);
        return { success: false, error: error.message };
    }
}

async function handlePoiRequest(request, env) {
    // Initialize Firestore
    let firestore = null;
    try {
        if (env.FIREBASE_PROJECT_ID && env.FIREBASE_SERVICE_ACCOUNT) {
            const FIREBASE_PROJECT_ID = env.FIREBASE_PROJECT_ID;
            const FIREBASE_SERVICE_ACCOUNT = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
            firestore = new Firestore(FIREBASE_PROJECT_ID, FIREBASE_SERVICE_ACCOUNT);
        }
    } catch (error) {
        return { success: false, error: 'Firestore configuration error.' };
    }

    if (!firestore) {
        return { success: false, error: 'POI data store not configured.' };
    }
    
    const url = new URL(request.url);
    const userId = url.pathname.split('/')[2];

    switch(request.method) {
        case 'POST':
            try {
                const poiData = await request.json();
                if (!poiData.userId || !poiData.markedBy || !poiData.reason) {
                     return { success: false, error: 'Missing required POI data.' };
                }
                return await setPersonOfInterestStatus(poiData.userId, poiData, firestore);
            } catch (e) {
                return { success: false, error: 'Invalid POI data format.' };
            }
        
        case 'GET':
             if (!userId) return { success: false, error: 'User ID is required.' };
             const status = await getPersonOfInterestStatus(userId, firestore);
             return { success: true, data: status };

        case 'DELETE':
            if (!userId) return { success: false, error: 'User ID is required.' };
            try {
                await setPersonOfInterestStatus(userId, { isPoi: false, markedBy: 'System', reason: 'Removed' }, firestore);
                return { success: true };
            } catch (error) {
                return { success: false, error: error.message };
            }

        default:
            return { success: false, error: `Method ${request.method} not allowed.` };
    }
}

async function handleRequest(request, env) {
    if (request.method === 'OPTIONS') {
        return withCorsHeaders(new Response(null, { status: 204 }));
    }

    const rateLimitResult = await applyRateLimit(request);
    if (rateLimitResult) {
        return withCorsHeaders(rateLimitResult);
    }

    const url = new URL(request.url);
    const endpoint = url.pathname.split('/')[1];
    
    let result;

    try {
        // Initialize Firestore for requests that need it
        let firestore = null;
        let cache = null;

        try {
            if (env.FIREBASE_PROJECT_ID && env.FIREBASE_SERVICE_ACCOUNT && 
                (endpoint === 'poi' || url.searchParams.has('lookup') || endpoint === 'graph')) {
                const FIREBASE_PROJECT_ID = env.FIREBASE_PROJECT_ID;
                const FIREBASE_SERVICE_ACCOUNT = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
                firestore = new Firestore(FIREBASE_PROJECT_ID, FIREBASE_SERVICE_ACCOUNT);
                cache = new HybridCache(firestore);
            }
        } catch (error) {
            console.warn('Failed to initialize Firestore, continuing without persistent cache:', error.message);
        }

        if (endpoint === 'poi') {
            result = await handlePoiRequest(request, env);
        } else if (endpoint === 'graph' && request.method === 'POST') {
            const body = await request.json();
            const isDeepSearch = body.deepSearch === true;
            result = await handleFriendGraph(body.users, env, isDeepSearch);
        } else if (url.searchParams.has('lookup')) {
            const lookupQuery = url.searchParams.get('lookup');
            if (firestore && cache) {
                result = await handleUserLookup(lookupQuery, env, firestore, cache);
            } else {
                // Fallback to simple lookup without Firestore
                subrequestManager.reset();
                try {
                    let user;
                    if (isNaN(lookupQuery)) {
                        const usernameResponse = await subrequestManager.makeRequest('https://users.roblox.com/v1/usernames/users', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ usernames: [lookupQuery] })
                        });
                        const partialUser = usernameResponse.data?.[0];
                        if (!partialUser) throw new Error('User not found');
                        user = await subrequestManager.makeRequest(`https://users.roblox.com/v1/users/${partialUser.id}`);
                    } else {
                        user = await subrequestManager.makeRequest(`https://users.roblox.com/v1/users/${parseInt(lookupQuery)}`);
                    }

                    result = {
                        success: true,
                        profile: {
                            ...user,
                            avatarUrl: 'https://placehold.co/150x150/1f222c/FFFFFF?text=?',
                            friendCount: 0,
                            isPotentialRisk: false,
                            isPOI: false
                        },
                        friends: [],
                        bannedFriends: [],
                        banHistory: []
                    };
                } catch (error) {
                    result = { success: false, error: error.message };
                }
            }
        } else if (endpoint === 'bans' || endpoint === 'banlist') {
            result = await handleBanList(env);
        } else {
            result = await handleBanList(env);
        }

        return withCorsHeaders(new Response(JSON.stringify(result), {
            headers: { 'Content-Type': 'application/json' }
        }));

    } catch (error) {
        console.error('Request error:', error);
        return withCorsHeaders(new Response(
            JSON.stringify({
                success: false,
                error: 'Internal server error',
                details: error.message
            }),
            {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            }
        ));
    }
}

export default {
    async fetch(request, env, ctx) {
        return await handleRequest(request, env);
    }
};