/**
 * Client-side worker for handling Roblox API calls
 * This eliminates Cloudflare Workers subrequest limits by moving processing to the browser
 */

class RobloxAPIClient {
    constructor() {
        this.rateLimiter = new RateLimiter();
        this.cache = new Map();
        this.CACHE_DURATION = 60 * 60 * 1000; // 1 hour
    }

    async makeRequest(url, options = {}) {
        await this.rateLimiter.waitForSlot();
        
        try {
            const response = await fetch(url, {
                ...options,
                headers: {
                    'Accept': 'application/json',
                    ...options.headers
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error(`Request failed for ${url}:`, error);
            throw error;
        }
    }

    async getUserByUsername(username) {
        const cacheKey = `user:${username.toLowerCase()}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) return cached;

        try {
            const data = await this.makeRequest('https://users.roblox.com/v1/usernames/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ usernames: [username] })
            });
            
            const user = data.data?.[0];
            if (user) {
                this.setCache(cacheKey, user);
                this.setCache(`user:${user.id}`, user);
            }
            return user;
        } catch (error) {
            console.error(`Failed to get user ${username}:`, error);
            return null;
        }
    }

    async getUserById(userId) {
        const cacheKey = `user:${userId}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) return cached;

        try {
            const data = await this.makeRequest(`https://users.roblox.com/v1/users/${userId}`);
            this.setCache(cacheKey, data);
            return data;
        } catch (error) {
            console.error(`Failed to get user ${userId}:`, error);
            return null;
        }
    }

    async getUserFriends(userId) {
        const cacheKey = `friends:${userId}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) return cached;

        try {
            const data = await this.makeRequest(`https://friends.roblox.com/v1/users/${userId}/friends`);
            const friends = data.data || [];
            this.setCache(cacheKey, friends);
            return friends;
        } catch (error) {
            console.error(`Failed to get friends for ${userId}:`, error);
            return [];
        }
    }

    async getUserAvatar(userId, size = 150) {
        const cacheKey = `avatar:${userId}:${size}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) return cached;

        try {
            const data = await this.makeRequest(
                `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=${size}x${size}&format=Png&isCircular=false`
            );
            
            const avatarUrl = data.data?.[0]?.imageUrl || `https://placehold.co/${size}x${size}/1f222c/FFFFFF?text=?`;
            this.setCache(cacheKey, avatarUrl);
            return avatarUrl;
        } catch (error) {
            console.error(`Failed to get avatar for ${userId}:`, error);
            return `https://placehold.co/${size}x${size}/1f222c/FFFFFF?text=?`;
        }
    }

    async getBatchUserDetails(userIds) {
        const uncachedIds = userIds.filter(id => !this.getFromCache(`userdetails:${id}`));
        
        if (uncachedIds.length === 0) {
            return userIds.map(id => this.getFromCache(`userdetails:${id}`));
        }

        const results = new Map();
        
        // Process in smaller batches to avoid rate limits
        for (let i = 0; i < uncachedIds.length; i += 50) {
            const batch = uncachedIds.slice(i, i + 50);
            
            try {
                const data = await this.makeRequest('https://users.roblox.com/v1/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userIds: batch })
                });
                
                data.data?.forEach(user => {
                    this.setCache(`userdetails:${user.id}`, user);
                    results.set(user.id, user);
                });
            } catch (error) {
                console.error(`Failed to get batch user details:`, error);
            }
            
            // Small delay between batches
            if (i + 50 < uncachedIds.length) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }
        
        return userIds.map(id => results.get(id) || this.getFromCache(`userdetails:${id}`) || { id, name: 'Unknown' });
    }

    getFromCache(key) {
        const item = this.cache.get(key);
        if (!item) return null;
        
        if (Date.now() - item.timestamp > this.CACHE_DURATION) {
            this.cache.delete(key);
            return null;
        }
        
        return item.data;
    }

    setCache(key, data) {
        this.cache.set(key, {
            data,
            timestamp: Date.now()
        });
    }
}

class RateLimiter {
    constructor(requestsPerSecond = 10) {
        this.requestsPerSecond = requestsPerSecond;
        this.requests = [];
    }

    async waitForSlot() {
        const now = Date.now();
        
        // Remove requests older than 1 second
        this.requests = this.requests.filter(time => now - time < 1000);
        
        if (this.requests.length >= this.requestsPerSecond) {
            const oldestRequest = Math.min(...this.requests);
            const waitTime = 1000 - (now - oldestRequest) + 10; // Add 10ms buffer
            await new Promise(resolve => setTimeout(resolve, waitTime));
            return this.waitForSlot(); // Recursive call after waiting
        }
        
        this.requests.push(now);
    }
}

// Export for use in your HTML files
window.RobloxAPIClient = RobloxAPIClient;