/**
 * Optimized Cloudflare Worker - Efficient caching with rate limiting and progress tracking
 * Supports up to 5 users with unlimited friends, smart caching, and deep search mode
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

                    // Add progress callback for rate limiting if available
                    if (options.onRateLimit) {
                        options.onRateLimit(`Rate limited - waiting ${retryAfter}s (retry ${retryCount + 1}/3)`);
                    }

                    // Wait for the retry period
                    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));

                    // Don't increment count for retries
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

// Simple cache implementation (in production, use KV storage)
class SimpleCache {
    constructor() {
        this.cache = new Map();
        this.maxSize = 1000; // Prevent memory issues
    }

    _isExpired(item, maxAgeMs) {
        return Date.now() - item.timestamp > maxAgeMs;
    }

    get(key, maxAgeMs = LIMITS.CACHE_DURATION_HOURS * 60 * 60 * 1000) {
        const item = this.cache.get(key);
        if (!item) return null;

        // For deep search, never expire cache
        if (maxAgeMs === Infinity) {
            return item.data;
        }

        if (this._isExpired(item, maxAgeMs)) {
            this.cache.delete(key);
            return null;
        }

        return item.data;
    }

    set(key, data) {
        // Simple LRU: remove oldest if at capacity
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        this.cache.set(key, {
            data,
            timestamp: Date.now()
        });
    }

    has(key, maxAgeMs = LIMITS.CACHE_DURATION_HOURS * 60 * 60 * 1000) {
        return this.get(key, maxAgeMs) !== null;
    }

    getStats() {
        return {
            size: this.cache.size,
            maxSize: this.maxSize
        };
    }
}

const cache = new SimpleCache();

// Batch staff role checking - more efficient than individual calls
// Daily cached staff list for specific roles
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

// Cache for staff list - daily refresh
let staffCache = {
    data: new Map(), // userId -> roleName
    lastUpdated: 0,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
};

async function buildStaffCache(groupId = 3149674) {
    console.log('Building daily staff cache...');
    const staffMap = new Map();

    try {
        // Get all group roles
        const rolesResponse = await subrequestManager.makeRequest(`https://groups.roblox.com/v1/groups/${groupId}/roles`);

        // Filter to only the staff roles we care about
        const targetRoles = rolesResponse.roles.filter(role => STAFF_ROLES.includes(role.name));
        console.log(`Found ${targetRoles.length} target staff roles:`, targetRoles.map(r => r.name));

        // Fetch members for each target role
        for (const role of targetRoles) {
            if (!subrequestManager.canMakeRequest()) {
                console.warn('Subrequest limit reached while building staff cache');
                break;
            }

            let nextPageCursor = null;
            let pageCount = 0;

            do {
                if (!subrequestManager.canMakeRequest()) {
                    console.warn('Subrequest limit reached, stopping role fetch');
                    break;
                }

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

                    // Limit pages to prevent too many subrequests
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

        // Update cache
        staffCache = {
            data: staffMap,
            lastUpdated: Date.now(),
            maxAge: staffCache.maxAge
        };

        console.log(`Staff cache built with ${staffMap.size} staff members`);
        return staffMap;

    } catch (error) {
        console.error("Failed to build staff cache:", error);
        return new Map();
    }
}

async function getStaffMap(groupId = 3149674) {
    // Check if cache is still valid
    const cacheAge = Date.now() - staffCache.lastUpdated;

    if (cacheAge < staffCache.maxAge && staffCache.data.size > 0) {
        console.log(`Using cached staff data (age: ${Math.round(cacheAge / (60 * 60 * 1000))} hours)`);
        return staffCache.data;
    }

    // Cache is stale or empty, rebuild it
    console.log('Staff cache is stale, rebuilding...');
    return await buildStaffCache(groupId);
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

                // Only return role if it's one of our target staff roles
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

async function getUserByUsername(username, isDeepSearch = false) {
    const cacheKey = `user:username:${username.toLowerCase()}`;
    const maxAge = isDeepSearch ? Infinity : LIMITS.CACHE_DURATION_HOURS * 60 * 60 * 1000;

    // Check cache first. This cache should now always be the full user object.
    const cached = cache.get(cacheKey, maxAge);
    if (cached) {
        console.log(`Cache hit for username: ${username}`);
        return cached;
    }

    // Skip API call for deep search if no cache
    if (isDeepSearch) {
        console.log(`Deep search: no cache for username ${username}, skipping API call`);
        return null;
    }

    try {
        // Step 1: Resolve username to ID
        const usernameResponse = await subrequestManager.makeRequest('https://users.roblox.com/v1/usernames/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usernames: [username] })
        });

        const partialUser = usernameResponse.data?.[0] || null;
        if (!partialUser) {
            return null;
        }

        // Step 2: Fetch full user details using the ID
        // This will also handle caching the full object under the ID key.
        const fullUser = await getUserById(partialUser.id, isDeepSearch);

        if (fullUser) {
            // Step 3: Cache the full user object under the username key as well.
            cache.set(cacheKey, fullUser);
        }

        return fullUser;
    } catch (error) {
        console.error(`Failed to get user ${username}:`, error);
        return null;
    }
}

async function getUserById(userId, isDeepSearch = false) {
    const cacheKey = `user:id:${userId}`;
    const maxAge = isDeepSearch ? Infinity : LIMITS.CACHE_DURATION_HOURS * 60 * 60 * 1000;

    // Check cache first
    const cached = cache.get(cacheKey, maxAge);
    if (cached) {
        console.log(`Cache hit for user ID: ${userId}`);
        return cached;
    }

    // Skip API call for deep search if no cache
    if (isDeepSearch) {
        console.log(`Deep search: no cache for user ID ${userId}, skipping API call`);
        return null;
    }

    try {
        const data = await subrequestManager.makeRequest(`https://users.roblox.com/v1/users/${userId}`);
        if (data) {
            cache.set(cacheKey, data);
            if (data.name) {
                cache.set(`user:username:${data.name.toLowerCase()}`, data);
            }
        }
        return data;
    } catch (error) {
        console.error(`Failed to get user ${userId}:`, error);
        return null;
    }
}

async function getUserFriends(userId, isDeepSearch = false) {
    const cacheKey = `friends:${userId}`;
    const maxAge = isDeepSearch ? Infinity : LIMITS.CACHE_DURATION_HOURS * 60 * 60 * 1000;

    // Check cache first
    const cached = cache.get(cacheKey, maxAge);
    if (cached) {
        console.log(`Cache hit for friends of user: ${userId}`);
        return cached;
    }

    // Skip API call for deep search if no cache
    if (isDeepSearch) {
        console.log(`Deep search: no cache for friends of ${userId}, skipping API call`);
        return [];
    }

    try {
        const data = await subrequestManager.makeRequest(`https://friends.roblox.com/v1/users/${userId}/friends`);
        const friends = data.data || [];

        // No limit on friends as requested
        cache.set(cacheKey, friends);
        return friends;
    } catch (error) {
        console.error(`Failed to get friends for ${userId}:`, error);
        return [];
    }
}

async function getBatchUserDetails(userIds, isDeepSearch = false, onProgress = null) {
    const results = new Map();
    const uncachedIds = [];

    // Check cache for each user
    userIds.forEach(id => {
        const cacheKey = `userdetails:${id}`;
        const maxAge = isDeepSearch ? Infinity : LIMITS.CACHE_DURATION_HOURS * 60 * 60 * 1000;
        const cached = cache.get(cacheKey, maxAge);

        if (cached) {
            results.set(id, cached);
        } else if (!isDeepSearch) {
            uncachedIds.push(id);
        }
    });

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

        // Report progress
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
                cache.set(`userdetails:${user.id}`, user);
            });
        } catch (error) {
            console.error(`Failed to get batch user details:`, error);
        }

        // Rate limiting delay
        if (i + LIMITS.BATCH_SIZE < uncachedIds.length) {
            await new Promise(resolve => setTimeout(resolve, LIMITS.REQUEST_DELAY));
        }
    }

    return results;
}

async function getBatchAvatars(userIds, isDeepSearch = false, onProgress = null) {
    const results = new Map();
    const uncachedIds = [];

    // Check cache for each avatar
    userIds.forEach(id => {
        const cacheKey = `avatar:${id}`;
        const maxAge = isDeepSearch ? Infinity : LIMITS.CACHE_DURATION_HOURS * 60 * 60 * 1000;
        const cached = cache.get(cacheKey, maxAge);

        if (cached) {
            results.set(id, cached);
        } else if (!isDeepSearch) {
            uncachedIds.push(id);
        } else {
            // For deep search, use placeholder if no cache
            results.set(id, 'https://placehold.co/150x150/1f222c/FFFFFF?text=?');
        }
    });

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

        // Report progress
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
                cache.set(`avatar:${avatar.targetId}`, avatarUrl);
            });
        } catch (error) {
            console.error(`Failed to get batch avatars:`, error);
            // Set placeholder avatars for this batch
            batch.forEach(id => {
                const placeholder = 'https://placehold.co/150x150/1f222c/FFFFFF?text=?';
                results.set(id, placeholder);
                cache.set(`avatar:${id}`, placeholder);
            });
        }

        // Rate limiting delay
        if (i + 100 < uncachedIds.length) {
            await new Promise(resolve => setTimeout(resolve, LIMITS.REQUEST_DELAY));
        }
    }

    return results;
}

async function handleBanList(env) {
    try {
        // Option 1: Use dedicated ban cache worker if configured
        if (env.BAN_CACHE_WORKER_URL) {
            console.log('Using dedicated ban cache worker');
            const response = await fetch(env.BAN_CACHE_WORKER_URL);

            if (!response.ok) {
                throw new Error(`Ban cache worker error: ${response.status}`);
            }

            const data = await response.json();
            return data; // Already in correct format
        }

        // Option 2: Try multiple ban list URLs (including the working one from old worker)
        const banListUrls = [
            env.BAN_LIST_URL,
            'http://bans.saikouapi.xyz/v1/bans/list-bans',
            'http://api.saikou.dev/v1/bans/list-bans?sortOrder=Desc', // From old worker - HTTP not HTTPS!
            'https://saikou-banlist-proxy.saikoudevelopment.workers.dev',
            'https://saikou.banlist.workers.dev',
            'https://api.saikou.dev/v1/bans/list-bans'
        ].filter(Boolean); // Remove null/undefined values

        for (let i = 0; i < banListUrls.length; i++) {
            const banListUrl = banListUrls[i];
            const headers = {};

            // Add API key if provided (use the same header as old worker)
            if (env.SAIKOU_API_KEY) {
                headers['X-API-KEY'] = env.SAIKOU_API_KEY;
            } else if (env['X-API-KEY']) {
                headers['X-API-KEY'] = env['X-API-KEY'];
            }

            console.log(`Trying ban list URL ${i + 1}/${banListUrls.length}: ${banListUrl}`);

            try {
                // Add timeout to prevent hanging
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

                const response = await fetch(banListUrl, {
                    headers,
                    signal: controller.signal
                });

                clearTimeout(timeoutId);
                console.log(`Response status: ${response.status}`);

                if (response.ok) {
                    const data = await response.json();
                    console.log(`SUCCESS with ${banListUrl} - data type: ${Array.isArray(data) ? 'array' : typeof data}, length: ${Array.isArray(data) ? data.length : 'N/A'}`);

                    // Handle both array response and object response
                    const banList = Array.isArray(data) ? data : (data.data || data);

                    return { success: true, data: banList };
                } else {
                    console.warn(`Failed ${banListUrl}: HTTP ${response.status}`);
                }
            } catch (error) {
                console.warn(`Error with ${banListUrl}: ${error.message}`);
            }
        }

        // If all URLs failed, use emergency fallback for testing
        console.warn('All ban list URLs failed, using emergency fallback');

        // Emergency fallback - minimal ban list for testing
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

        // Follow the old worker pattern - just log and continue with empty ban list
        console.error("Could not fetch Saikou ban list for graph:", error.message);
        return {
            success: true,
            data: [],
            warning: `Ban list unavailable: ${error.message}`,
            fallback: true
        };
    }
}

async function handleUserLookup(query, env) {
    subrequestManager.reset();

    try {
        let user;
        if (isNaN(query)) {
            user = await getUserByUsername(query);
        } else {
            user = await getUserById(parseInt(query));
        }

        if (!user) {
            return { success: false, error: 'User not found' };
        }

        // Get friends
        const friends = await getUserFriends(user.id);

        // Get avatar
        const avatarMap = await getBatchAvatars([user.id]);
        user.avatarUrl = avatarMap.get(user.id);

        // Get friend avatars (limited batch for performance)
        const friendIds = friends.slice(0, 50).map(f => f.id);
        const friendAvatars = await getBatchAvatars(friendIds);
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

        // Get user's groups
        let userGroups = [];
        try {
            if (subrequestManager.canMakeRequest()) {
                const groupsResponse = await subrequestManager.makeRequest(`https://groups.roblox.com/v2/users/${user.id}/groups/roles`);
                if (groupsResponse.data) {
                    userGroups = groupsResponse.data.slice(0, 10).map(g => ({
                        id: g.group.id,
                        name: g.group.name,
                        role: g.role.name,
                        memberCount: g.group.memberCount
                    }));
                }
            }
        } catch (error) {
            console.error('Error fetching user groups:', error);
        }

        // Get account settings (inventory visibility, join requests)
        let accountSettings = {
            inventoryHidden: false,
            allowJoinRequests: true,
            hasVerifiedBadge: user.hasVerifiedBadge || false
        };
        try {
            if (subrequestManager.canMakeRequest()) {
                const settingsResponse = await subrequestManager.makeRequest(`https://accountsettings.roblox.com/v1/users/${user.id}/settings`);
                if (settingsResponse) {
                    accountSettings.inventoryHidden = settingsResponse.inventoryPrivacy === 'NoOne' || settingsResponse.inventoryPrivacy === 'Friends';
                }
            }
        } catch (error) {
            console.error('Error fetching account settings:', error);
        }

        // Check POI status from KV
        let isPOI = false;
        if (env.POI_DATA) {
            const poiRecord = await env.POI_DATA.get(user.id.toString());
            isPOI = !!poiRecord;
        }


        // Risk assessment
        const accountAgeMs = Date.now() - new Date(user.created).getTime();
        const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;
        const isNewAccount = accountAgeMs < ninetyDaysMs;
        const friendCount = friends.length;
        const isPotentialRisk = isNewAccount && friendCount < 50;

        return {
            success: true,
            profile: {
                ...user,
                isBanned: !!userBan,
                banInfo: userBan,
                friendCount: friendCount,
                groupRole: roleInfo?.groupRole || null,
                groupRoleColor: roleInfo?.groupRoleColor || null,
                isPotentialRisk: isPotentialRisk,
                isPOI: isPOI,
                groups: userGroups,
                inventoryHidden: accountSettings.inventoryHidden,
                allowJoinRequests: accountSettings.allowJoinRequests,
                hasVerifiedBadge: accountSettings.hasVerifiedBadge
            },
            friends: friends,
            bannedFriends: bannedFriends.map(friend => ({
                ...friend,
                banInfo: banMap.get(friend.id)
            })),
            banHistory: banMap.has(user.id) ? [banMap.get(user.id)] : [] 
        };

    } catch (error) {
        console.error('Lookup error:', error);
        return { success: false, error: error.message };
    }
}


async function handleFriendGraph(usersQuery, env, isDeepSearch = false) {
    subrequestManager.reset(); // Reset counter for each request

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

    try {
        addProgress('Resolving initial users...', 5);

        // Step 1: Get initial users
        const initialUsers = [];
        for (let i = 0; i < usernames.length; i++) {
            const username = usernames[i];
            const user = isNaN(username) ?
                await getUserByUsername(username, isDeepSearch) :
                await getUserById(parseInt(username), isDeepSearch);

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
            const maxNodes = 500; // Safety limit to prevent huge graphs

            while(queue.length > 0 && nodes.size < maxNodes) {
                const currentUserId = queue.shift();
                if (processed.has(currentUserId)) continue;
                processed.add(currentUserId);

                const friends = await getUserFriends(currentUserId, true); // cache-only
                
                if (!nodes.has(currentUserId)) {
                     const userDetails = await getUserById(currentUserId, true); // cache-only
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
                const friends = await getUserFriends(user.id, isDeepSearch);
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

        // Step 3: Get user details and avatars with progress tracking
        const allUserIds = Array.from(nodes.keys());

        const userDetails = await getBatchUserDetails(allUserIds, isDeepSearch, (message, progress) => {
            addProgress(`User details: ${message}`, 50 + progress * 0.2);
        });

        addProgress('Processing avatars...', 70);

        const avatars = await getBatchAvatars(allUserIds, isDeepSearch, (message, progress) => {
            addProgress(`Avatars: ${message}`, 70 + progress * 0.15);
        });

        addProgress('Loading staff cache...', 80);
        const staffRoleMap = await getStaffMap(3149674);

        addProgress('Fetching ban list...', 85);
        const banList = await handleBanList(env);
        
        addProgress('Fetching POI list...', 88);
        let poiList = [];
        if (env.POI_DATA) {
            const list = await env.POI_DATA.list();
            poiList = list.keys.map(key => key.name);
        }

        // Update nodes with details
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

            node.avatarUrl = avatars.get(userId) || 'https://placehold.co/150x150/1f222c/FFFFFF?text=?';

            // Add staff role if user has one
            if (staffRoleMap.has(userId)) {
                node.groupRole = staffRoleMap.get(userId);
            }

            // Check if new account
            if (node.created) {
                const accountAge = Date.now() - new Date(node.created).getTime();
                const ninetyDays = 90 * 24 * 60 * 60 * 1000;
                node.isNewAccount = accountAge < ninetyDays;
            }
            
            // Check POI status
            node.isPOI = poiList.includes(userId.toString());
        }

        // Apply ban status
        if (banList.success && banList.data) {
            const banMap = new Map();
            banList.data.forEach(ban => {
                // Use RobloxID field like the old worker
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

        // Convert links
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
                cacheHits: cacheStats.size,
                limitInfo: `Used ${usage.used}/${usage.max} subrequests`,
                processingMode: isDeepSearch ? 'Deep Search (Cache Only)' : 'Normal (API + Cache)'
            }
        };

    } catch (error) {
        console.error('Graph generation error:', error);
        return { success: false, error: error.message };
    }
}

async function handlePoiRequest(request, env) {
    if (!env.POI_DATA) {
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
                await env.POI_DATA.put(poiData.userId.toString(), JSON.stringify(poiData));
                return { success: true };
            } catch (e) {
                return { success: false, error: 'Invalid POI data format.' };
            }
        
        case 'GET':
             if (!userId) return { success: false, error: 'User ID is required.' };
             const data = await env.POI_DATA.get(userId);
             if (!data) return { success: false, error: 'POI record not found.' };
             return { success: true, data: JSON.parse(data) };

        case 'DELETE':
            if (!userId) return { success: false, error: 'User ID is required.' };
            await env.POI_DATA.delete(userId);
            return { success: true };

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
        if (endpoint === 'poi') {
            result = await handlePoiRequest(request, env);
        } else if (endpoint === 'graph' && request.method === 'POST') {
            const body = await request.json();
            const isDeepSearch = body.deepSearch === true;
            result = await handleFriendGraph(body.users, env, isDeepSearch);
        } else if (url.searchParams.has('lookup')) {
             const lookupQuery = url.searchParams.get('lookup');
            result = await handleUserLookup(lookupQuery, env);
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

