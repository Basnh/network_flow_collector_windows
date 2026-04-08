/* Enhanced Dashboard JavaScript */

class SecurityDashboard {
    constructor() {
        try {
            console.log('🛡️ Initializing Security Dashboard with error protection...');
            
            this.init();
            // Removed theme toggle - this.setupThemeToggle();
            this.setupRealTimeUpdates();
            this.setupNotifications();
            this.setupAnimations();
            
            console.log('✅ Security Dashboard initialized successfully');
            
        } catch (error) {
            console.error('❌ Security Dashboard initialization failed:', error);
            if (window.handleJavaScriptError) {
                window.handleJavaScriptError(error, 'security-dashboard-init');
            }
        }
    }

    init() {
        try {
            // Initialize theme - keeping light theme as default
            document.documentElement.setAttribute('data-theme', 'light');
            
            // Show loading complete
            setTimeout(() => {
                this.hideLoading();
            }, 1000);
            
        } catch (error) {
            console.error('❌ Security Dashboard init failed:', error);
            if (window.handleJavaScriptError) {
                window.handleJavaScriptError(error, 'security-dashboard-setup');
            }
        }
    }

    /* Theme toggle system removed per user request */

    // Real-time Updates
    setupRealTimeUpdates() {
        try {
            console.log('🔄 Setting up real-time updates...');
            
            // Use safe intervals if available
            if (window.setSafeInterval) {
                // Update dashboard stats every 30 seconds
                this.updateInterval = window.setSafeInterval(() => {
                    this.fetchDashboardStats();
                }, 30000, 'enhanced-dashboard-stats');

                // Update agent status every 10 seconds
                this.agentStatusInterval = window.setSafeInterval(() => {
                    this.updateAgentStatus();
                }, 10000, 'enhanced-agent-status');
            } else {
                // Fallback to regular intervals with error handling
                this.updateInterval = setInterval(() => {
                    try {
                        this.fetchDashboardStats();
                    } catch (error) {
                        console.error('Dashboard stats update error:', error);
                    }
                }, 30000);

                this.agentStatusInterval = setInterval(() => {
                    try {
                        this.updateAgentStatus();
                    } catch (error) {
                        console.error('Agent status update error:', error);
                    }
                }, 10000);
            }

            // Add real-time activity feed
            this.setupActivityFeed();
            
            console.log('✅ Real-time updates configured successfully');
            
        } catch (error) {
            console.error('❌ Failed to setup real-time updates:', error);
            if (window.handleJavaScriptError) {
                window.handleJavaScriptError(error, 'enhanced-realtime-setup');
            }
        }
    }

    async fetchDashboardStats() {
        try {
            const response = await fetch('/api/dashboard/stats');
            if (response.ok) {
                const data = await response.json();
                this.updateStatsCards(data);
            } else {
                console.warn('Failed to fetch dashboard stats:', response.status, response.statusText);
            }
        } catch (error) {
            console.error('Error fetching stats:', error);
            // Track error for global error recovery system
            if (window.trackError) {
                window.trackError(error, 'fetchDashboardStats');
            }
        }
    }

    updateStatsCards(data) {
        try {
            // Animate number changes with error protection
            if (data.total_agents !== undefined) {
                this.animateNumber('total-agents', data.total_agents);
            }
            if (data.active_agents !== undefined) {
                this.animateNumber('active-agents', data.active_agents);
            }
            if (data.isolated_agents !== undefined) {
                this.animateNumber('isolated-agents', data.isolated_agents);
            }
            
            // Update threat level indicator
            if (data.threat_level !== undefined) {
                this.updateThreatLevel(data.threat_level);
            }
        } catch (error) {
            console.error('Error updating stats cards:', error);
            if (window.trackError) {
                window.trackError(error, 'updateStatsCards');
            }
        }
    }

    animateNumber(elementId, newValue) {
        try {
            const element = document.getElementById(elementId);
            if (!element) {
                console.warn(`Element with ID '${elementId}' not found for number animation`);
                return;
            }

            const currentValue = parseInt(element.textContent) || 0;
            
            // Skip animation if values are the same
            if (currentValue === newValue) return;
            
            const increment = newValue > currentValue ? 1 : -1;
            const step = Math.abs(newValue - currentValue) / 20;

            let counter = currentValue;
            const timer = setInterval(() => {
                try {
                    counter += increment * step;
                    if ((increment > 0 && counter >= newValue) || (increment < 0 && counter <= newValue)) {
                        counter = newValue;
                        clearInterval(timer);
                    }
                    element.textContent = Math.floor(counter);
                } catch (innerError) {
                    console.error('Error during number animation step:', innerError);
                    clearInterval(timer);
                    element.textContent = newValue; // Fallback to final value
                }
            }, 50);
        } catch (error) {
            console.error(`Error animating number for element '${elementId}':`, error);
            if (window.trackError) {
                window.trackError(error, `animateNumber-${elementId}`);
            }
            
            // Fallback: just set the value directly
            try {
                const element = document.getElementById(elementId);
                if (element) element.textContent = newValue;
            } catch (fallbackError) {
                console.error('Fallback animation also failed:', fallbackError);
            }
        }
    }

    // Notifications System
    setupNotifications() {
        // Create toast container if not exists
        if (!document.querySelector('.toast-container')) {
            const container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
    }

    showNotification(message, type = 'info', icon = '') {
        const container = document.querySelector('.toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type} show`;
        toast.innerHTML = `
            <div class="toast-header">
                <span class="me-2">${icon}</span>
                <strong class="me-auto">System</strong>
                <small class="text-muted">${new Date().toLocaleTimeString()}</small>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        `;

        container.appendChild(toast);

        // Auto remove after 5 seconds
        setTimeout(() => {
            toast.remove();
        }, 5000);

        // Add click to dismiss
        toast.querySelector('.btn-close').onclick = () => toast.remove();
    }

    // Activity Feed
    setupActivityFeed() {
        try {
            // Create activity feed if not exists
            const sidebar = document.querySelector('.activity-sidebar');
            if (sidebar) {
                // Use safe interval if available
                if (window.setSafeInterval) {
                    this.activityInterval = window.setSafeInterval(() => {
                        try {
                            this.fetchLatestActivity();
                        } catch (error) {
                            console.error('Error in activity feed update:', error);
                            if (window.trackError) window.trackError(error);
                        }
                    }, 15000, 'enhanced-activity-feed');
                } else {
                    this.activityInterval = setInterval(() => {
                        try {
                            this.fetchLatestActivity();
                        } catch (error) {
                            console.error('Error in activity feed update:', error);
                        }
                    }, 15000);
                }
            }
        } catch (error) {
            console.error('Error setting up activity feed:', error);
            if (window.trackError) {
                window.trackError(error, 'setupActivityFeed');
            }
        }
    }

    async fetchLatestActivity() {
        try {
            const response = await fetch('/api/activity/latest');
            if (response.ok) {
                const activities = await response.json();
                this.updateActivityFeed(activities);
            } else {
                console.warn('Failed to fetch activity:', response.status, response.statusText);
            }
        } catch (error) {
            console.error('Error fetching activity:', error);
            // Track error for global error recovery system
            if (window.trackError) {
                window.trackError(error, 'fetchLatestActivity');
            }
        }
    }

    updateActivityFeed(activities) {
        const feed = document.querySelector('.activity-feed');
        if (!feed) return;

        activities.forEach(activity => {
            const item = document.createElement('div');
            item.className = 'activity-item new';
            item.innerHTML = `
                <div class="d-flex justify-content-between">
                    <span class="fw-bold">${activity.title}</span>
                    <small class="text-muted">${activity.time}</small>
                </div>
                <p class="small mb-0 text-muted">${activity.description}</p>
            `;
            
            feed.insertBefore(item, feed.firstChild);
            
            // Remove old items (keep max 10)
            while (feed.children.length > 10) {
                feed.removeChild(feed.lastChild);
            }
        });
    }

    // Animations & Effects
    setupAnimations() {
        // Intersection Observer for fade-in animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                }
            });
        }, observerOptions);

        // Observe all cards and elements
        document.querySelectorAll('.card, .enhanced-card').forEach(el => {
            observer.observe(el);
        });

        // Add loading states to buttons
        this.setupLoadingStates();
    }

    setupLoadingStates() {
        document.querySelectorAll('[data-loading]').forEach(button => {
            button.addEventListener('click', (e) => {
                this.showButtonLoading(e.target);
            });
        });
    }

    showButtonLoading(button) {
        const originalText = button.innerHTML;
        button.innerHTML = '<span class="loading-spinner me-2"></span>Loading...';
        button.disabled = true;

        // Simulate async operation
        setTimeout(() => {
            button.innerHTML = originalText;
            button.disabled = false;
        }, 2000);
    }

    hideLoading() {
        const loader = document.querySelector('.page-loader');
        if (loader) {
            loader.style.opacity = '0';
            setTimeout(() => loader.remove(), 300);
        }
    }

    // Agent Status Updates
    async updateAgentStatus() {
        try {
            const agentCards = document.querySelectorAll('[data-agent-id]');
            for (const card of agentCards) {
                const agentId = card.dataset.agentId;
                try {
                    const response = await fetch(`/api/agents/${agentId}/status`);
                    if (response.ok) {
                        const data = await response.json();
                        this.updateAgentCard(card, data);
                    } else {
                        console.warn(`Failed to fetch agent ${agentId} status:`, response.status);
                    }
                } catch (error) {
                    console.error(`Error updating agent ${agentId}:`, error);
                    if (window.trackError) {
                        window.trackError(error, `updateAgent-${agentId}`);
                    }
                }
            }
        } catch (error) {
            console.error('Error in updateAgentStatus:', error);
            if (window.trackError) {
                window.trackError(error, 'updateAgentStatus');
            }
        }
    }

    updateAgentCard(card, data) {
        const statusElement = card.querySelector('.status-indicator');
        const lastSeenElement = card.querySelector('.last-seen');
        
        if (statusElement) {
            statusElement.className = `status-indicator status-${data.status}`;
        }
        
        if (lastSeenElement) {
            lastSeenElement.textContent = `Last seen: ${data.last_seen}`;
        }

        // Show notification for status changes
        if (data.status_changed) {
            this.showNotification(
                `Agent ${data.hostname} is now ${data.status}`,
                data.status === 'online' ? 'success' : 'warning',
                '<i class="fas fa-server"></i>'
            );
        }
    }

    // Utility Methods
    formatTime(timestamp) {
        const UTC_PLUS_7_OFFSET = 7 * 60 * 60 * 1000;
        const date = new Date(timestamp);
        const adjustedDate = new Date(date.getTime() + UTC_PLUS_7_OFFSET);
        return adjustedDate.toLocaleTimeString();
    }

    cleanup() {
        try {
            console.log('🧹 Cleaning up SecurityDashboard intervals...');
            
            // Clear intervals using safe cleanup if available
            if (window.clearSafeInterval) {
                if (this.updateInterval) {
                    window.clearSafeInterval(this.updateInterval);
                    this.updateInterval = null;
                }
                if (this.agentStatusInterval) {
                    window.clearSafeInterval(this.agentStatusInterval);
                    this.agentStatusInterval = null;
                }
                if (this.activityInterval) {
                    window.clearSafeInterval(this.activityInterval);
                    this.activityInterval = null;
                }
            } else {
                // Fallback to regular clearInterval
                if (this.updateInterval) {
                    clearInterval(this.updateInterval);
                    this.updateInterval = null;
                }
                if (this.agentStatusInterval) {
                    clearInterval(this.agentStatusInterval);
                    this.agentStatusInterval = null;
                }
                if (this.activityInterval) {
                    clearInterval(this.activityInterval);
                    this.activityInterval = null;
                }
            }
            
            console.log('✅ SecurityDashboard cleanup completed');
        } catch (error) {
            console.error('❌ Error during cleanup:', error);
        }
    }
}

// Sound System for Alerts
class AlertSoundSystem {
    constructor() {
        this.audioContext = null;
        this.setupAudioContext();
    }

    setupAudioContext() {
        try {
            this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
        } catch (error) {
            console.warn('Web Audio API not supported');
        }
    }

    playAlert(type = 'warning') {
        try {
            if (!this.audioContext) return;

            const oscillator = this.audioContext.createOscillator();
            const gainNode = this.audioContext.createGain();

            oscillator.connect(gainNode);
            gainNode.connect(this.audioContext.destination);

            // Different frequencies for different alert types
            const frequencies = {
                success: 800,
                warning: 600,
                error: 400,
                critical: 300
            };

            oscillator.frequency.setValueAtTime(frequencies[type] || 600, this.audioContext.currentTime);
            gainNode.gain.setValueAtTime(0.1, this.audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.5);

            oscillator.start(this.audioContext.currentTime);
            oscillator.stop(this.audioContext.currentTime + 0.5);
        } catch (error) {
            console.error('Error playing alert sound:', error);
            // Track error but don't crash the application
            if (window.trackError) {
                window.trackError(error, 'alertSoundPlay');
            }
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    try {
        console.log('🚀 Initializing Enhanced Security Dashboard...');
        
        // Initialize security dashboard with error protection
        window.securityDashboard = new SecurityDashboard();
        console.log('✅ SecurityDashboard initialized');
        
        // Initialize alert sound system with error protection
        window.alertSounds = new AlertSoundSystem();
        console.log('✅ AlertSoundSystem initialized');
        
        // Add CSS animations with error protection
        try {
            const style = document.createElement('style');
            style.textContent = `
                .animate-in {
                    animation: fadeInUp 0.6s ease-out;
                }
                
                @keyframes fadeInUp {
                    from {
                        opacity: 0;
                        transform: translateY(30px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }
                
                .page-loader {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: var(--bg-primary);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 9999;
                    transition: opacity 0.3s ease;
                }
            `;
            document.head.appendChild(style);
            console.log('✅ CSS animations added');
        } catch (error) {
            console.error('❌ Error adding CSS animations:', error);
            if (window.trackError) window.trackError(error, 'css-animations');
        }
        
        console.log('🎉 Enhanced Security Dashboard fully initialized');
        
    } catch (error) {
        console.error('❌ Critical error initializing Enhanced Security Dashboard:', error);
        if (window.trackError) {
            window.trackError(error, 'enhanced-dashboard-init');
        }
        
        // Show user-friendly error
        if (window.showErrorOverlay) {
            window.showErrorOverlay('Failed to initialize enhanced dashboard features. Please refresh the page.');
        }
    }
});

// Cleanup on page unload with error protection
window.addEventListener('beforeunload', () => {
    try {
        if (window.securityDashboard) {
            window.securityDashboard.cleanup();
        }
    } catch (error) {
        console.error('Error during page unload cleanup:', error);
    }
});