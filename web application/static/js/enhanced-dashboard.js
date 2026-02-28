/* Enhanced Dashboard JavaScript */

class SecurityDashboard {
    constructor() {
        this.init();
        this.setupThemeToggle();
        this.setupRealTimeUpdates();
        this.setupNotifications();
        this.setupAnimations();
    }

    init() {
        // Initialize theme from localStorage
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        // Show loading complete
        setTimeout(() => {
            this.hideLoading();
        }, 1000);
    }

    // Theme Toggle System
    setupThemeToggle() {
        // Create theme toggle button if not exists
        if (!document.querySelector('.theme-toggle')) {
            const toggleBtn = document.createElement('button');
            toggleBtn.className = 'btn theme-toggle';
            toggleBtn.innerHTML = '<i class="fas fa-moon" id="theme-icon"></i>';
            toggleBtn.addEventListener('click', this.toggleTheme.bind(this));
            document.body.appendChild(toggleBtn);
        }

        this.updateThemeIcon();
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        this.updateThemeIcon();
        
        // Show notification
        this.showNotification(
            `Switched to ${newTheme} mode`, 
            'success', 
            `<i class="fas fa-${newTheme === 'dark' ? 'moon' : 'sun'}"></i>`
        );
    }

    updateThemeIcon() {
        const themeIcon = document.getElementById('theme-icon');
        const currentTheme = document.documentElement.getAttribute('data-theme');
        
        if (themeIcon) {
            themeIcon.className = currentTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }

    // Real-time Updates
    setupRealTimeUpdates() {
        // Update dashboard stats every 30 seconds
        this.updateInterval = setInterval(() => {
            this.fetchDashboardStats();
        }, 30000);

        // Update agent status every 10 seconds
        this.agentStatusInterval = setInterval(() => {
            this.updateAgentStatus();
        }, 10000);

        // Add real-time activity feed
        this.setupActivityFeed();
    }

    async fetchDashboardStats() {
        try {
            const response = await fetch('/api/dashboard/stats');
            if (response.ok) {
                const data = await response.json();
                this.updateStatsCards(data);
            }
        } catch (error) {
            console.error('Error fetching stats:', error);
        }
    }

    updateStatsCards(data) {
        // Animate number changes
        this.animateNumber('total-agents', data.total_agents);
        this.animateNumber('active-agents', data.active_agents);
        this.animateNumber('isolated-agents', data.isolated_agents);
        
        // Update threat level indicator
        this.updateThreatLevel(data.threat_level);
    }

    animateNumber(elementId, newValue) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const currentValue = parseInt(element.textContent) || 0;
        const increment = newValue > currentValue ? 1 : -1;
        const step = Math.abs(newValue - currentValue) / 20;

        let counter = currentValue;
        const timer = setInterval(() => {
            counter += increment * step;
            if ((increment > 0 && counter >= newValue) || (increment < 0 && counter <= newValue)) {
                counter = newValue;
                clearInterval(timer);
            }
            element.textContent = Math.floor(counter);
        }, 50);
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
        // Create activity feed if not exists
        const sidebar = document.querySelector('.activity-sidebar');
        if (sidebar) {
            this.activityInterval = setInterval(() => {
                this.fetchLatestActivity();
            }, 15000);
        }
    }

    async fetchLatestActivity() {
        try {
            const response = await fetch('/api/activity/latest');
            if (response.ok) {
                const activities = await response.json();
                this.updateActivityFeed(activities);
            }
        } catch (error) {
            console.error('Error fetching activity:', error);
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
        const agentCards = document.querySelectorAll('[data-agent-id]');
        agentCards.forEach(async (card) => {
            const agentId = card.dataset.agentId;
            try {
                const response = await fetch(`/api/agents/${agentId}/status`);
                if (response.ok) {
                    const data = await response.json();
                    this.updateAgentCard(card, data);
                }
            } catch (error) {
                console.error(`Error updating agent ${agentId}:`, error);
            }
        });
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
        return new Date(timestamp).toLocaleTimeString();
    }

    cleanup() {
        // Clear intervals when page unloads
        if (this.updateInterval) clearInterval(this.updateInterval);
        if (this.agentStatusInterval) clearInterval(this.agentStatusInterval);
        if (this.activityInterval) clearInterval(this.activityInterval);
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
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.securityDashboard = new SecurityDashboard();
    window.alertSounds = new AlertSoundSystem();
    
    // Add CSS animations
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
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.securityDashboard) {
        window.securityDashboard.cleanup();
    }
});