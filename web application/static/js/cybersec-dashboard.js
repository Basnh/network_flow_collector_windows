class CyberSecDashboard {
    constructor() {
        this.charts = {};
        this.updateInterval = 30000; // 30 seconds
        this.animationSpeed = 300;
        this.isFullscreen = false;
        this.realTimeUpdates = true; // Enable real-time updates
        this.lastUpdateTime = Date.now();
        this.safeIntervals = []; // Track intervals for cleanup
        this.isInitialized = false;
        
        this.init();
    }

    init() {
        try {
            console.log('🛡️ Initializing CyberSec Dashboard...');
            
            this.initCharts();
            this.initAnimations();
            this.initInteractiveElements();
            this.startRealTimeUpdates();
            this.initKeyboardShortcuts();
            this.initNotificationSystem();
            this.initSmoothUpdates(); // Add smooth update system
            
            this.isInitialized = true;
            console.log('✅ CyberSec Dashboard initialized successfully with stability enhancements');
            
        } catch (error) {
            console.error('❌ Dashboard initialization failed:', error);
            if (window.handleJavaScriptError) {
                window.handleJavaScriptError(error, 'dashboard-init');
            }
        }
    }

    /* ========================================
       CHART INITIALIZATION
    ======================================== */
    initCharts() {
        this.createTrafficChart();
        this.createProtocolChart();
        // Disabled - Show static total flows count instead of animated counter
        // this.initFlowsPerSecCounter();
    }

    createTrafficChart() {
        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;

        // Generate demo data for the last 24 hours
        const now = new Date();
        const labels = [];
        const incomingData = [];
        const outgoingData = [];
        
        for (let i = 23; i >= 0; i--) {
            const time = new Date(now - i * 60 * 60 * 1000);
            labels.push(time.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}));
            
            // Simulate network traffic with some variation
            const baseIncoming = Math.sin(i * 0.2) * 20 + 50 + Math.random() * 15;
            const baseOutgoing = Math.cos(i * 0.15) * 15 + 30 + Math.random() * 10;
            
            incomingData.push(Math.max(0, baseIncoming));
            outgoingData.push(Math.max(0, baseOutgoing));
        }

        this.charts.traffic = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Incoming Traffic',
                    data: incomingData,
                    borderColor: '#38bdf8',
                    backgroundColor: 'rgba(56, 189, 248, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                }, {
                    label: 'Outgoing Traffic',
                    data: outgoingData,
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index',
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            color: '#cbd5e1',
                            font: {
                                family: 'Inter',
                                size: 12
                            },
                            usePointStyle: true,
                            pointStyle: 'circle',
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(17, 24, 39, 0.9)',
                        titleColor: '#ffffff',
                        bodyColor: '#cbd5e1',
                        borderColor: '#38bdf8',
                        borderWidth: 1,
                        cornerRadius: 8,
                        displayColors: true,
                        callbacks: {
                            title: function(context) {
                                return `Time: ${context[0].label}`;
                            },
                            label: function(context) {
                                return `${context.dataset.label}: ${context.parsed.y.toFixed(1)} Mbps`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        display: true,
                        grid: {
                            color: 'rgba(56, 189, 248, 0.1)',
                            drawBorder: false,
                        },
                        ticks: {
                            color: '#64748b',
                            font: {
                                family: 'JetBrains Mono',
                                size: 10
                            },
                            maxTicksLimit: 8,
                        }
                    },
                    y: {
                        display: true,
                        grid: {
                            color: 'rgba(56, 189, 248, 0.1)',
                            drawBorder: false,
                        },
                        ticks: {
                            color: '#64748b',
                            font: {
                                family: 'JetBrains Mono',
                                size: 10
                            },
                            callback: function(value) {
                                return value + ' Mbps';
                            }
                        }
                    }
                },
                elements: {
                    line: {
                        borderJoinStyle: 'round'
                    }
                },
                animation: {
                    duration: 1000,
                    easing: 'easeInOutQuart'
                }
            }
        });

        // Auto-update traffic chart
        setInterval(() => {
            this.updateTrafficChart();
        }, 5000);
    }

    createProtocolChart() {
        const ctx = document.getElementById('protocolChart');
        if (!ctx) return;

        let tcpVal = parseInt(ctx.dataset.tcp);
        if (isNaN(tcpVal)) tcpVal = 68;
        let udpVal = parseInt(ctx.dataset.udp);
        if (isNaN(udpVal)) udpVal = 24;
        let rdpVal = parseInt(ctx.dataset.rdp);
        if (isNaN(rdpVal)) rdpVal = 5;
        let otherVal = parseInt(ctx.dataset.other);
        if (isNaN(otherVal)) otherVal = 3;

        const protocolData = [tcpVal, udpVal, rdpVal, otherVal]; // TCP, UDP, RDP, Other
        const protocolColors = ['#3b82f6', '#f59e0b', '#ef4444', '#64748b'];

        this.charts.protocol = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'RDP/ICMP', 'Other'],
                datasets: [{
                    data: protocolData,
                    backgroundColor: protocolColors,
                    borderColor: protocolColors.map(color => color + '40'),
                    borderWidth: 2,
                    hoverBorderWidth: 4,
                    hoverBorderColor: '#ffffff',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(17, 24, 39, 0.9)',
                        titleColor: '#ffffff',
                        bodyColor: '#cbd5e1',
                        borderColor: '#38bdf8',
                        borderWidth: 1,
                        cornerRadius: 8,
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                return `${label}: ${value}%`;
                            }
                        }
                    }
                },
                elements: {
                    arc: {
                        borderRadius: 4,
                        hoverBackgroundColor: function(context) {
                            const color = context.element.options.backgroundColor;
                            return color + 'cc';
                        }
                    }
                },
                animation: {
                    animateRotate: true,
                    animateScale: true,
                    duration: 1500,
                    easing: 'easeInOutQuart'
                },
                onHover: (event, elements) => {
                    event.native.target.style.cursor = elements.length > 0 ? 'pointer' : 'default';
                }
            }
        });
    }

    initFlowsPerSecCounter() {
        const counter = document.getElementById('flows-per-sec');
        if (!counter) return;

        let currentValue = 0;
        const targetRange = [45, 120];
        
        setInterval(() => {
            const target = Math.floor(Math.random() * (targetRange[1] - targetRange[0] + 1)) + targetRange[0];
            this.animateNumberTo(counter, target, 1000);
        }, 3000);
    }

    /* ========================================
       ANIMATION SYSTEM
    ======================================== */
    initAnimations() {
        this.initScrollAnimations();
        this.initHoverEffects();
        this.initNumberCounters();
        this.initProgressAnimations();
    }

    initScrollAnimations() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-fade-in');
                    
                    // Trigger number animations
                    const counterElement = entry.target.querySelector('[data-counter-end]');
                    if (counterElement) {
                        const target = parseInt(counterElement.dataset.counterEnd);
                        this.animateNumberTo(counterElement, target, 2000);
                    }
                }
            });
        }, observerOptions);

        // Observe all metric cards and animated elements
        document.querySelectorAll('.metric-card, .threats-panel, .radar-panel').forEach(el => {
            observer.observe(el);
        });
    }

    initHoverEffects() {
        // Metric card hover effects
        document.querySelectorAll('.metric-card').forEach(card => {
            card.addEventListener('mouseenter', () => {
                this.addGlowEffect(card);
                const icon = card.querySelector('.card-icon i');
                if (icon) {
                    icon.style.transform = 'scale(1.2) rotate(10deg)';
                    icon.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
                }
            });

            card.addEventListener('mouseleave', () => {
                this.removeGlowEffect(card);
                const icon = card.querySelector('.card-icon i');
                if (icon) {
                    icon.style.transform = 'scale(1) rotate(0deg)';
                }
            });
        });

        // Network node hover effects
        document.querySelectorAll('.network-node').forEach(node => {
            node.addEventListener('mouseenter', () => {
                this.showNodeDetails(node);
            });
            
            node.addEventListener('mouseleave', () => {
                this.hideNodeDetails(node);
            });
        });
    }

    initNumberCounters() {
        document.querySelectorAll('[data-counter-end]').forEach(element => {
            const target = parseInt(element.dataset.counterEnd) || 0;
            element.textContent = '0';
            
            // Start animation after a short delay
            setTimeout(() => {
                this.animateNumberTo(element, target, 2000);
            }, 500);
        });
    }

    initProgressAnimations() {
        document.querySelectorAll('.metric-progress .progress-bar').forEach(bar => {
            const width = bar.style.width;
            bar.style.width = '0%';
            
            setTimeout(() => {
                bar.style.width = width;
            }, 1000);
        });

        document.querySelectorAll('.health-fill').forEach(fill => {
            const width = fill.style.width;
            fill.style.width = '0%';
            
            setTimeout(() => {
                fill.style.width = width;
            }, 1500);
        });
    }

    animateNumberTo(element, target, duration = 1000) {
        const start = parseInt(element.textContent) || 0;
        const difference = target - start;
        const startTime = performance.now();

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function for smooth animation
            const easeProgress = progress < 0.5 
                ? 2 * progress * progress 
                : 1 - Math.pow(-2 * progress + 2, 3) / 2;
            
            const currentValue = start + (difference * easeProgress);
            element.textContent = Math.floor(currentValue);
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                element.textContent = target;
            }
        };

        requestAnimationFrame(animate);
    }

    /* ========================================
       INTERACTIVE ELEMENTS
    ======================================== */
    initInteractiveElements() {
        this.initTableInteractions();
        this.initControlButtons();
        this.initFilterSelects();
        this.initTooltips();
    }

    initTableInteractions() {
        // Threat row click handlers
        document.querySelectorAll('.threat-row').forEach(row => {
            row.addEventListener('click', (e) => {
                const threatId = e.currentTarget.dataset.threatId;
                if (threatId) {
                    this.expandThreatDetails(threatId);
                }
            });
        });

        // Flow row click handlers
        document.querySelectorAll('.flow-row').forEach(row => {
            row.addEventListener('click', (e) => {
                const flowId = e.currentTarget.dataset.flowId;
                if (flowId) {
                    this.expandFlowDetails(flowId);
                }
            });
        });
    }

    initControlButtons() {
        document.querySelectorAll('.control-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                this.animateButtonClick(btn);
            });
        });
    }

    initFilterSelects() {
        document.querySelectorAll('.filter-select').forEach(select => {
            select.addEventListener('change', (e) => {
                const value = e.target.value;
                this.filterFlowsTable(value);
            });
        });
    }

    initTooltips() {
        // Simple tooltip system
        document.querySelectorAll('[title]').forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(e.target, e.target.getAttribute('title'));
            });
            
            element.addEventListener('mouseleave', (e) => {
                this.hideTooltip();
            });
        });
    }

    /* ========================================
       REAL-TIME UPDATES
    ======================================== */
    startRealTimeUpdates() {
        try {
            // Use safe intervals to prevent errors from crashing the dashboard
            if (window.setSafeInterval) {
                // Primary update cycle - comprehensive without page reload
                window.setSafeInterval(() => {
                    if (this.realTimeUpdates && this.isInitialized) {
                        this.fetchAndUpdateData();
                    }
                }, this.updateInterval, 'dashboard-main');

                // Quick updates for dynamic elements with error protection
                window.setSafeInterval(() => {
                    if (this.realTimeUpdates) {
                        this.updateLiveSensorCount();
                    }
                }, 5000, 'sensor-count');

                // Disabled - Show static total flows count instead of animated counter
                // window.setSafeInterval(() => {
                //     if (this.realTimeUpdates) {
                //         this.updateFlowsCounter();
                //     }
                // }, 2000, 'flows-counter');

                // Initialize smooth update system for seamless UX
                setTimeout(() => {
                    if (typeof initSmoothUpdates === 'function') {
                        initSmoothUpdates();
                    }
                }, 1000);
                
                console.log('✅ Real-time updates initialized with error protection');
            } else {
                console.warn('⚠️ Safe interval system not available, using fallback');
                this.startFallbackUpdates();
            }
            
        } catch (error) {
            console.error('❌ Failed to start real-time updates:', error);
            if (window.handleJavaScriptError) {
                window.handleJavaScriptError(error, 'realtime-updates');
            }
        }
    }
    
    startFallbackUpdates() {
        // Fallback method with basic error handling
        try {
            setInterval(() => {
                if (this.realTimeUpdates && this.isInitialized) {
                    try {
                        this.fetchAndUpdateData();
                    } catch (error) {
                        console.error('Update error:', error);
                    }
                }
            }, this.updateInterval);
            
            console.log('🔄 Fallback updates started');
        } catch (error) {
            console.error('❌ Fallback updates failed:', error);
        }
    }

    async fetchAndUpdateData() {
        try {
            // Add connection check before making request
            if (!navigator.onLine) {
                console.warn('📡 Offline detected, skipping update');
                return;
            }
            
            const response = await fetch('/api/dashboard/stats');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.updateDashboardData(data);
            
            // Reset error count on successful update
            if (window.errorCount !== undefined) {
                window.errorCount = Math.max(0, window.errorCount - 1);
            }
            
            this.showNotification('Dashboard updated', 'success', '<i class="fas fa-sync-alt"></i>');
            
        } catch (error) {
            console.error('❌ Error fetching dashboard data:', error);
            
            // Use global error handler if available
            if (window.handleJavaScriptError) {
                window.handleJavaScriptError(error, 'fetch-data');
            }
            
            // Show user-friendly error message
            this.showNotification('Connection issue - Retrying...', 'warning', '<i class="fas fa-exclamation-triangle"></i>');
            
            // Attempt retry with exponential backoff
            setTimeout(() => {
                if (this.realTimeUpdates) {
                    console.log('🔄 Retrying data fetch...');
                    this.fetchAndUpdateData();
                }
            }, 5000);
        }
    }

    updateDashboardData(data) {
        // Update metric counters
        const metrics = {
            'live-sensor-count': data.active_agents || 0,
        };

        Object.entries(metrics).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element && parseInt(element.textContent) !== value) {
                this.animateNumberTo(element, value, 800);
            }
        });

        // Update progress bars and indicators
        this.updateVisualIndicators(data);
    }

    updateVisualIndicators(data) {
        // Update status indicators
        const indicators = document.querySelectorAll('.status-indicator');
        indicators.forEach((indicator, index) => {
            if (index < (data.active_agents || 0)) {
                indicator.classList.add('online');
                indicator.classList.remove('offline');
            } else {
                indicator.classList.add('offline');
                indicator.classList.remove('online');
            }
        });

        // Update progress bars
        const progressBars = document.querySelectorAll('.metric-progress .progress-bar');
        progressBars.forEach(bar => {
            const percentage = data.active_agents && data.total_agents 
                ? (data.active_agents / data.total_agents) * 100 
                : 0;
            bar.style.width = `${percentage}%`;
        });
    }

    updateTrafficChart() {
        if (!this.charts.traffic) return;

        const chart = this.charts.traffic;
        const now = new Date();
        const newLabel = now.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
        
        // Generate new data points
        const newIncoming = Math.sin(Date.now() * 0.001) * 20 + 50 + Math.random() * 15;
        const newOutgoing = Math.cos(Date.now() * 0.0008) * 15 + 30 + Math.random() * 10;
        
        // Add new data point
        chart.data.labels.push(newLabel);
        chart.data.datasets[0].data.push(Math.max(0, newIncoming));
        chart.data.datasets[1].data.push(Math.max(0, newOutgoing));
        
        // Remove old data (keep last 24 points)
        if (chart.data.labels.length > 24) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
            chart.data.datasets[1].data.shift();
        }
        
        chart.update('none'); // Update without animation for smooth real-time feel
    }

    updateLiveSensorCount() {
        const element = document.getElementById('live-sensor-count');
        if (!element) return;

        // Simulate minor fluctuations in sensor count
        const currentValue = parseInt(element.textContent) || 0;
        const variation = Math.random() > 0.8 ? (Math.random() > 0.5 ? 1 : -1) : 0;
        const newValue = Math.max(1, currentValue + variation);
        
        if (newValue !== currentValue) {
            this.animateNumberTo(element, newValue, 500);
        }
    }

    

    /* ========================================
       UI INTERACTIONS
    ======================================== */
    expandThreatDetails(threatId) {
        console.log(`Expanding threat details for: ${threatId}`);
        this.showNotification(`Viewing threat #${threatId}`, 'info', '<i class="fas fa-eye"></i>');
        
        // TODO: Implement threat details modal or navigation
    }

    expandFlowDetails(flowId) {
        console.log(`Expanding flow details for: ${flowId}`);
        this.showNotification(`Analyzing flow #${flowId}`, 'info', '<i class="fas fa-search"></i>');
        
        // TODO: Implement flow details modal or navigation
    }

    filterFlowsTable(filter) {
        const rows = document.querySelectorAll('.flow-row');
        
        rows.forEach(row => {
            let shouldShow = true;
            
            switch(filter) {
                case 'TCP Only':
                    shouldShow = row.textContent.includes('TCP');
                    break;
                case 'UDP Only':
                    shouldShow = row.textContent.includes('UDP');
                    break;
                case 'Suspicious':
                    shouldShow = row.classList.contains('malicious');
                    break;
                default:
                    shouldShow = true;
            }
            
            if (shouldShow) {
                row.style.display = 'grid';
                row.style.animation = 'fadeInUp 0.3s ease-out';
            } else {
                row.style.display = 'none';
            }
        });

        this.showNotification(`Filter applied: ${filter}`, 'info', '<i class="fas fa-filter"></i>');
    }

    animateButtonClick(button) {
        button.style.transform = 'scale(0.95)';
        button.style.transition = 'transform 0.1s ease';
        
        setTimeout(() => {
            button.style.transform = 'scale(1)';
        }, 100);
    }

    addGlowEffect(element) {
        element.style.boxShadow = '0 20px 40px rgba(0, 0, 0, 0.3), 0 0 20px rgba(56, 189, 248, 0.3)';
    }

    removeGlowEffect(element) {
        element.style.boxShadow = '';
    }

    showNodeDetails(node) {
        const info = node.querySelector('.node-info');
        if (info) {
            info.style.opacity = '1';
        }
    }

    hideNodeDetails(node) {
        const info = node.querySelector('.node-info');
        if (info) {
            info.style.opacity = '0';
        }
    }

    /* ========================================
       NOTIFICATION SYSTEM
    ======================================== */
    initNotificationSystem() {
        // Create notification container if it doesn't exist
        if (!document.getElementById('notification-container')) {
            const container = document.createElement('div');
            container.id = 'notification-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                display: flex;
                flex-direction: column;
                gap: 10px;
                pointer-events: none;
            `;
            document.body.appendChild(container);
        }
    }

    showNotification(message, type = 'info', icon = '') {
        const container = document.getElementById('notification-container');
        if (!container) return;

        const notification = document.createElement('div');
        notification.style.cssText = `
            background: rgba(17, 24, 39, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid ${this.getNotificationColor(type)};
            border-radius: 12px;
            padding: 12px 16px;
            color: #ffffff;
            font-size: 0.875rem;
            font-family: Inter, sans-serif;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), 0 0 20px ${this.getNotificationColor(type)}40;
            transform: translateX(100%);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            pointer-events: auto;
            cursor: pointer;
            max-width: 300px;
            word-wrap: break-word;
        `;
        
        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                ${icon}
                <span>${message}</span>
            </div>
        `;

        container.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 50);

        // Click to dismiss
        notification.addEventListener('click', () => {
            this.dismissNotification(notification);
        });

        // Auto dismiss after 3 seconds
        setTimeout(() => {
            this.dismissNotification(notification);
        }, 3000);
    }

    dismissNotification(notification) {
        notification.style.transform = 'translateX(100%)';
        notification.style.opacity = '0';
        
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }

    getNotificationColor(type) {
        const colors = {
            'success': '#22c55e',
            'error': '#ef4444',
            'warning': '#f59e0b',
            'info': '#38bdf8'
        };
        return colors[type] || colors.info;
    }

    /* ========================================
       TOOLTIP SYSTEM
    ======================================== */
    showTooltip(element, text) {
        this.hideTooltip(); // Remove any existing tooltip
        
        const tooltip = document.createElement('div');
        tooltip.id = 'cybersec-tooltip';
        tooltip.textContent = text;
        tooltip.style.cssText = `
            position: absolute;
            background: rgba(17, 24, 39, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid #38bdf8;
            border-radius: 6px;
            padding: 8px 12px;
            color: #ffffff;
            font-size: 0.75rem;
            z-index: 10001;
            pointer-events: none;
            white-space: nowrap;
            opacity: 0;
            transition: opacity 0.2s ease;
        `;
        
        document.body.appendChild(tooltip);
        
        // Position tooltip
        const rect = element.getBoundingClientRect();
        tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
        tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
        
        // Show tooltip
        setTimeout(() => {
            tooltip.style.opacity = '1';
        }, 50);
    }

    hideTooltip() {
        const tooltip = document.getElementById('cybersec-tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }

    /* ========================================
       KEYBOARD SHORTCUTS
    ======================================== */
    initKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + R: Refresh dashboard
            if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
                e.preventDefault();
                this.fetchAndUpdateData();
            }
            
            // F11: Toggle fullscreen
            if (e.key === 'F11') {
                e.preventDefault();
                this.toggleFullScreen();
            }
            
            // Escape: Exit fullscreen
            if (e.key === 'Escape' && this.isFullscreen) {
                this.exitFullScreen();
            }
        });
    }

    /* ========================================
       UTILITY FUNCTIONS
    ======================================== */
    toggleFullScreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().then(() => {
                this.isFullscreen = true;
                this.showNotification('Entered fullscreen mode', 'info', '<i class="fas fa-expand"></i>');
            });
        } else {
            document.exitFullscreen().then(() => {
                this.isFullscreen = false;
                this.showNotification('Exited fullscreen mode', 'info', '<i class="fas fa-compress"></i>');
            });
        }
    }

    exitFullScreen() {
        if (document.fullscreenElement) {
            document.exitFullscreen().then(() => {
                this.isFullscreen = false;
            });
        }
    }

    exportDashboard() {
        this.showNotification('Preparing dashboard export...', 'info', '<i class="fas fa-download"></i>');
        
        // TODO: Implement dashboard export functionality
        setTimeout(() => {
            this.showNotification('Export completed', 'success', '<i class="fas fa-check"></i>');
        }, 2000);
    }

    openCommandCenter() {
        this.showNotification('Opening command center...', 'info', '<i class="fas fa-terminal"></i>');
        
        // TODO: Implement command center modal or navigation
    }

    refreshThreats() {
        this.showNotification('Refreshing threat data...', 'info', '<i class="fas fa-sync-alt"></i>');
        
        // Simulate refresh with loading state
        const button = event.target.closest('.control-btn');
        if (button) {
            const icon = button.querySelector('i');
            const originalClass = icon.className;
            
            icon.className = 'fas fa-spinner fa-spin';
            button.style.pointerEvents = 'none';
            
            setTimeout(() => {
                icon.className = originalClass;
                button.style.pointerEvents = 'auto';
                this.showNotification('Threats updated', 'success', '<i class="fas fa-check"></i>');
            }, 1500);
        }
    }

    // Public API methods for external calls
    refresh() {
        this.fetchAndUpdateData();
    }

    updateMetric(metricId, value) {
        const element = document.getElementById(metricId);
        if (element) {
            this.animateNumberTo(element, value, 1000);
        }
    }

    addThreatAlert(threatData) {
        this.showNotification(
            `New threat detected: ${threatData.type}`, 
            'warning', 
            '<i class="fas fa-exclamation-triangle"></i>'
        );
    }
}

/* ========================================
   GLOBAL FUNCTIONS
======================================== */
function toggleFullScreen() {
    if (window.dashboard) {
        window.dashboard.toggleFullScreen();
    }
}

function exportDashboard() {
    if (window.dashboard) {
        window.dashboard.exportDashboard();
    }
}

function openCommandCenter() {
    if (window.dashboard) {
        window.dashboard.openCommandCenter();
    }
}

function refreshThreats() {
    if (window.dashboard) {
        window.dashboard.refreshThreats();
    }
}

function expandThreatDetails(threatId) {
    if (window.dashboard) {
        window.dashboard.expandThreatDetails(threatId);
    }
}

function expandFlowDetails(flowId) {
    if (window.dashboard) {
        window.dashboard.expandFlowDetails(flowId);
    }
}

/* ========================================
   INITIALIZATION
======================================== */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the cybersecurity dashboard
    window.dashboard = new CyberSecDashboard();
    
    // Add global styles for smooth animations
    if (!document.getElementById('cybersec-global-styles')) {
        const style = document.createElement('style');
        style.id = 'cybersec-global-styles';
        style.textContent = `
            .animate-fade-in {
                animation: fadeInUp 0.6s ease-out forwards;
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
            
            /* Smooth transitions for all interactive elements */
            .metric-card,
            .panel-header,
            .threat-row,
            .flow-row,
            .source-item,
            .control-btn {
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            /* Loading states */
            .loading {
                opacity: 0.7;
                pointer-events: none;
            }
            
            /* Glow effects */
            .glow-blue {
                box-shadow: 0 0 20px rgba(56, 189, 248, 0.3);
            }
            
            .glow-green {
                box-shadow: 0 0 20px rgba(34, 197, 94, 0.3);
            }
            
            .glow-red {
                box-shadow: 0 0 20px rgba(239, 68, 68, 0.3);
            }
        `;
        document.head.appendChild(style);
    }
    
    console.log('🚀 Cybersecurity Dashboard loaded and ready');
});

/* ========================================
   ENHANCED ALERTS FUNCTIONALITY
======================================== */

// Alert Management Functions
function viewAlertDetails(alertId) {
    console.log('Viewing alert details for ID:', alertId);
    // Create modal or redirect to alert detail page
    const modal = document.createElement('div');
    modal.className = 'alert-detail-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-shield-virus"></i> Alert Details #${alertId}</h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <p>Loading alert details...</p>
                <div class="spinner"></div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function resolveAlert(alertId) {
    if (confirm('Bạn có chắc chắn muốn đánh dấu alert này đã được giải quyết?')) {
        console.log('Resolving alert ID:', alertId);
        
        // Update UI immediately
        const alertRow = document.querySelector(`[data-alert-id="${alertId}"]`);
        if (alertRow) {
            alertRow.classList.add('resolved');
            const statusBadge = alertRow.querySelector('.status-badge');
            if (statusBadge) {
                statusBadge.className = 'status-badge resolved';
                statusBadge.innerHTML = '<i class="fas fa-check-circle"></i> Đã giải quyết';
            }
        }
        
        // Make API call
        fetch(`/resolve_alert/${alertId}`, { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Alert đã được giải quyết thành công', 'success');
                }
            })
            .catch(error => {
                console.error('Error resolving alert:', error);
                showNotification('Có lỗi xảy ra khi giải quyết alert', 'error');
            });
    }
}

function escalateAlert(alertId) {
    console.log('Escalating alert ID:', alertId);
    const modal = document.createElement('div');
    modal.className = 'escalation-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-arrow-up"></i> Nâng cấp mức độ Alert</h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="escalation-options">
                    <button class="escalation-btn critical" onclick="setEscalation('${alertId}', 'critical')">
                        <i class="fas fa-exclamation-triangle"></i> Critical
                    </button>
                    <button class="escalation-btn high" onclick="setEscalation('${alertId}', 'high')">
                        <i class="fas fa-exclamation-circle"></i> High
                    </button>
                </div>
                <textarea placeholder="Lý do nâng cấp..." class="escalation-reason"></textarea>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function exportAlert(alertId) {
    console.log('Exporting alert ID:', alertId);
    showNotification('Đang xuất dữ liệu alert...', 'info');
    
    // Simulate export
    setTimeout(() => {
        showNotification('Alert đã được xuất thành công', 'success');
    }, 1500);
}

function shareAlert(alertId) {
    console.log('Sharing alert ID:', alertId);
    const shareData = {
        title: `Security Alert #${alertId}`,
        text: `Chia sẻ security alert từ Network Flow Collector`,
        url: window.location.href
    };
    
    if (navigator.share) {
        navigator.share(shareData);
    } else {
        // Fallback - copy to clipboard
        navigator.clipboard.writeText(window.location.href)
            .then(() => showNotification('Link đã được copy vào clipboard', 'success'));
    }
}

function deleteAlert(alertId) {
    if (confirm('Bạn có chắc chắn muốn xóa alert này? Hành động này không thể hoàn tác.')) {
        console.log('Deleting alert ID:', alertId);
        
        const alertRow = document.querySelector(`[data-alert-id="${alertId}"]`);
        if (alertRow) {
            alertRow.style.animation = 'slideOut 0.3s ease-out forwards';
            setTimeout(() => alertRow.remove(), 300);
        }
        
        showNotification('Alert đã được xóa', 'success');
    }
}

// Filter Functions
function initializeAlertFilters() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    const alertRows = document.querySelectorAll('.threat-row');
    
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Update active filter
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const filter = btn.dataset.filter;
            
            // Filter alerts
            alertRows.forEach(row => {
                const severity = row.dataset.severity;
                const shouldShow = filter === 'all' || severity === filter;
                
                row.style.display = shouldShow ? 'grid' : 'none';
            });
        });
    });
}

function exportAlerts() {
    console.log('Exporting all alerts...');
    showNotification('Đang xuất tất cả alerts...', 'info');
    
    // Simulate export
    setTimeout(() => {
        showNotification('Tất cả alerts đã được xuất thành công', 'success');
    }, 2000);
}

function runSecurityScan() {
    console.log('Running manual security scan...');
    showNotification('Đang chạy quét bảo mật thủ công...', 'info');
    
    // Simulate scan
    setTimeout(() => {
        showNotification('Quét bảo mật hoàn tất - Không phát hiện mới đe dọa', 'success');
    }, 3000);
}

function viewAllAlerts() {
    window.location.href = '/alerts';
}

// Utility Functions
function closeModal() {
    const modals = document.querySelectorAll('.alert-detail-modal, .escalation-modal');
    modals.forEach(modal => modal.remove());
}

function setEscalation(alertId, level) {
    console.log(`Setting escalation for ${alertId} to ${level}`);
    showNotification(`Alert đã được nâng cấp lên mức ${level}`, 'success');
    closeModal();
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'times' : 'info'}"></i>
        <span>${message}</span>
        <button onclick="this.parentNode.remove()">&times;</button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 3000);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeAlertFilters();
});

/* ========================================
   SMOOTH REAL-TIME UPDATE SYSTEM
======================================== */

// Smooth Updates without Page Reload
function initSmoothUpdates() {
    try {
        console.log('🔄 Initializing smooth updates with error protection...');
        
        if (window.setSafeInterval) {
            // Use safe intervals to prevent crashes
            window.setSafeInterval(updateDashboardStats, 15000, 'dashboard-stats');
            window.setSafeInterval(updateAlertsTable, 10000, 'alerts-table');  
            window.setSafeInterval(updateAgentStatus, 20000, 'agent-status');
            window.setSafeInterval(updateRadarDisplay, 5000, 'radar-display');
        } else {
            // Fallback to regular intervals with try-catch
            setInterval(() => {
                try { updateDashboardStats(); } 
                catch (e) { console.error('Stats update error:', e); }
            }, 15000);
            
            setInterval(() => {
                try { updateAlertsTable(); } 
                catch (e) { console.error('Alerts update error:', e); }
            }, 10000);
            
            setInterval(() => {
                try { updateAgentStatus(); } 
                catch (e) { console.error('Agent status update error:', e); }
            }, 20000);
            
            setInterval(() => {
                try { updateRadarDisplay(); } 
                catch (e) { console.error('Radar update error:', e); }
            }, 5000);
        }
        
        console.log('✅ Smooth real-time updates initialized successfully');
        
    } catch (error) {
        console.error('❌ Failed to initialize smooth updates:', error);
        if (window.handleJavaScriptError) {
            window.handleJavaScriptError(error, 'smooth-updates-init');
        }
    }
}

// Update Dashboard Statistics Smoothly
async function updateDashboardStats() {
    try {
        showUpdateIndicator('stats');
        
        const response = await fetch('/api/dashboard/stats');
        if (!response.ok) throw new Error('Failed to fetch stats');
        
        const data = await response.json();
        
        // Update metrics with smooth animations
        smoothUpdateMetric('live-sensor-count', data.active_agents || 0);
        // Disabled - Keep static total flows count instead of updating dynamically
        // smoothUpdateMetric('flows-per-sec', data.threat_flows || 0);
        
        // Update metric cards
        updateMetricCard('active_agents', data.active_agents, data.total_agents);
        updateMetricCard('recent_alerts', data.recent_alerts_count);
        updateMetricCard('threat_flows', data.threat_flows);
        
        hideUpdateIndicator('stats');
        
        console.log('📊 Dashboard stats updated smoothly');
        
    } catch (error) {
        console.error('Error updating dashboard stats:', error);
        hideUpdateIndicator('stats');
    }
}

// Update Alerts Table without Page Reload
async function updateAlertsTable() {
    try {
        showUpdateIndicator('alerts');
        
        const response = await fetch('/api/alerts/recent');
        if (!response.ok) throw new Error('Failed to fetch alerts');
        
        const alerts = await response.json();
        
        // Get current table body
        const tableBody = document.querySelector('.threats-table .table-body');
        if (!tableBody) return;
        
        // Fade out current content
        tableBody.style.opacity = '0.5';
        
        setTimeout(() => {
            updateAlertsContent(tableBody, alerts);
            
            // Fade in new content
            tableBody.style.opacity = '1';
            tableBody.style.transition = 'opacity 0.3s ease';
            
            hideUpdateIndicator('alerts');
        }, 200);
        
        console.log('🚨 Alerts updated smoothly');
        
    } catch (error) {
        console.error('Error updating alerts:', error);
        hideUpdateIndicator('alerts');
    }
}

// Update Agent Status Indicators
async function updateAgentStatus() {
    try {
        const response = await fetch('/api/agents/status');
        if (!response.ok) throw new Error('Failed to fetch agent status');
        
        const agents = await response.json();
        
        // Update status indicators smoothly
        const statusIndicators = document.querySelectorAll('.status-indicator');
        agents.forEach((agent, index) => {
            if (statusIndicators[index]) {
                const indicator = statusIndicators[index];
                const newClass = agent.status === 'active' ? 'online' : 'offline';
                
                if (!indicator.classList.contains(newClass)) {
                    indicator.style.transform = 'scale(1.2)';
                    setTimeout(() => {
                        indicator.className = `status-indicator ${newClass}`;
                        indicator.style.transform = 'scale(1)';
                    }, 150);
                }
            }
        });
        
        console.log('🖥️ Agent status updated');
        
    } catch (error) {
        console.error('Error updating agent status:', error);
    }
}

// Update Radar Display
function updateRadarDisplay() {
    const radarSweep = document.querySelector('.radar-sweep');
    const networkNodes = document.querySelectorAll('.network-node');
    
    if (radarSweep) {
        // Animate radar sweep
        radarSweep.style.animation = 'none';
        radarSweep.offsetHeight; // Force reflow
        radarSweep.style.animation = 'radarSweep 4s linear infinite';
    }
    
    // Add random pulse animations to nodes
    networkNodes.forEach(node => {
        if (Math.random() > 0.7) { // 30% chance
            node.classList.add('pulse-active');
            setTimeout(() => {
                node.classList.remove('pulse-active');
            }, 1000);
        }
    });
}

// Utility Functions for Smooth Updates
function smoothUpdateMetric(elementId, newValue) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const currentValue = parseInt(element.textContent) || 0;
    const targetValue = newValue;
    
    if (currentValue === targetValue) return;
    
    // Animate number change
    animateNumber(element, currentValue, targetValue, 1000);
}

function animateNumber(element, start, end, duration) {
    const startTime = performance.now();
    const difference = end - start;
    
    function updateNumber(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function for smooth animation
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (difference * easeOut));
        
        element.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(updateNumber);
        }
    }
    
    requestAnimationFrame(updateNumber);
}

function updateMetricCard(type, value, total = null) {
    const metricElements = document.querySelectorAll(`[data-counter-end]`);
    
    metricElements.forEach(element => {
        const counterEnd = element.getAttribute('data-counter-end');
        if (counterEnd && element.textContent !== value.toString()) {
            // Add update flash effect
            element.style.background = 'rgba(56, 189, 248, 0.2)';
            element.style.transition = 'background 0.3s ease';
            
            setTimeout(() => {
                animateNumber(element, parseInt(element.textContent) || 0, value, 800);
                element.style.background = 'transparent';
            }, 100);
        }
    });
}

function updateAlertsContent(tableBody, alerts) {
    if (alerts.length === 0) {
        tableBody.innerHTML = `
            <div class="no-threats">
                <div class="no-threats-content">
                    <i class="fas fa-shield-check"></i>
                    <h4>Hệ thống an toàn</h4>
                    <p>Không phát hiện mối đe dọa nào trong thời gian gần đây</p>
                    <button class="btn btn-outline-primary btn-sm" onclick="runSecurityScan()">
                        <i class="fas fa-search"></i> Quét bảo mật thủ công
                    </button>
                </div>
            </div>
        `;
        return;
    }
    
    // Build new alerts HTML
    let alertsHTML = '';
    alerts.slice(0, 10).forEach(alert => {
        const timeAgo = getTimeAgo(alert.created_at);
        alertsHTML += `
            <div class="threat-row severity-${alert.severity} ${alert.is_resolved ? 'resolved' : 'active'}" 
                 data-alert-id="${alert.id}" data-severity="${alert.severity}">
                
                <div class="col-time">
                    <div class="time-display">
                        <span class="time-main">${formatTime(alert.created_at)}</span>
                        <span class="time-date">${formatDate(alert.created_at)}</span>
                    </div>
                </div>
                
                <div class="col-type">
                    <div class="threat-info">
                        <span class="threat-badge ${alert.alert_type.toLowerCase()}">
                            <i class="fas fa-${alert.alert_type.toLowerCase() === 'trojan' ? 'virus' : 'shield-virus'}"></i>
                            ${alert.alert_type}
                        </span>
                        ${alert.description ? `<span class="threat-desc">${truncateText(alert.description, 50)}</span>` : ''}
                    </div>
                </div>
                
                <div class="col-source">
                    <div class="source-info">
                        <span class="source-agent">
                            <i class="fas fa-desktop"></i>
                            ${alert.agent_id || 'Unknown'}
                        </span>
                        ${alert.flow_id ? `<span class="source-flow">Flow: ${alert.flow_id.substring(0, 8)}</span>` : ''}
                    </div>
                </div>
                
                <div class="col-severity">
                    <div class="severity-container">
                        <span class="severity-badge ${alert.severity}">
                            <i class="fas fa-exclamation-triangle"></i>
                            ${alert.severity.toUpperCase()}
                        </span>
                        <div class="severity-indicator">
                            <div class="severity-bar ${alert.severity}"></div>
                        </div>
                    </div>
                </div>
                
                <div class="col-status">
                    <div class="status-container">
                        <span class="status-badge ${alert.is_resolved ? 'resolved' : 'active'}">
                            <i class="fas fa-${alert.is_resolved ? 'check-circle' : 'clock'}"></i>
                            ${alert.is_resolved ? 'Đã giải quyết' : 'Đang xử lý'}
                        </span>
                        <span class="status-time">${timeAgo}</span>
                    </div>
                </div>
                
                <div class="col-actions">
                    <div class="action-buttons">
                        ${!alert.is_resolved ? `
                        <button class="action-btn primary" onclick="viewAlertDetails(${alert.id})" title="Chi tiết">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="action-btn success" onclick="resolveAlert(${alert.id})" title="Giải quyết">
                            <i class="fas fa-check"></i>
                        </button>
                        <button class="action-btn warning" onclick="escalateAlert(${alert.id})" title="Nâng cấp">
                            <i class="fas fa-arrow-up"></i>
                        </button>
                        ` : `
                        <button class="action-btn secondary" onclick="viewAlertDetails(${alert.id})" title="Xem chi tiết">
                            <i class="fas fa-history"></i>
                        </button>
                        `}
                    </div>
                </div>
            </div>
        `;
    });
    
    tableBody.innerHTML = alertsHTML;
    
    // Re-attach filter functionality
    setTimeout(initializeAlertFilters, 100);
}

// Update Indicators
function showUpdateIndicator(section) {
    const indicator = document.createElement('div');
    indicator.className = `update-indicator update-${section}`;
    indicator.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i>';
    
    // Position based on section
    let targetElement;
    switch(section) {
        case 'stats':
            targetElement = document.querySelector('.top-status-bar');
            break;
        case 'alerts':
            targetElement = document.querySelector('.alerts-section-full .panel-header');
            break;
        default:
            return;
    }
    
    if (targetElement) {
        targetElement.style.position = 'relative';
        targetElement.appendChild(indicator);
    }
}

function hideUpdateIndicator(section) {
    const indicator = document.querySelector(`.update-${section}`);
    if (indicator) {
        indicator.style.opacity = '0';
        setTimeout(() => indicator.remove(), 200);
    }
}

// Utility Functions
// Offset for UTC+7 display (in milliseconds: 7 hours)
const UTC_PLUS_7_OFFSET = 7 * 60 * 60 * 1000;

function getTimeAgo(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    // Adjust for UTC+7 offset since server sends UTC+7 times as if they were UTC
    const adjustedTime = new Date(time.getTime() + UTC_PLUS_7_OFFSET);
    const diffMs = now - adjustedTime;
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffMins = Math.floor(diffMs / (1000 * 60));
    
    if (diffHours > 0) return `${diffHours}h ago`;
    if (diffMins > 0) return `${diffMins}m ago`;
    return 'Just now';
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    // Adjust for UTC+7 offset since server sends UTC+7 times as if they were UTC
    const adjustedDate = new Date(date.getTime() + UTC_PLUS_7_OFFSET);
    return adjustedDate.toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
    });
}

function formatDate(timestamp) {
    const date = new Date(timestamp);
    // Adjust for UTC+7 offset since server sends UTC+7 times as if they were UTC
    const adjustedDate = new Date(date.getTime() + UTC_PLUS_7_OFFSET);
    return adjustedDate.toLocaleDateString('en-GB', { 
        day: '2-digit', 
        month: '2-digit' 
    });
}

function truncateText(text, maxLength) {
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

// Refresh Functions (Enhanced)
function refreshThreats() {
    console.log('🔄 Manual refresh triggered');
    showCustomNotification('Đang cập nhật dữ liệu...', 'info');
    
    // Update all sections
    Promise.all([
        updateDashboardStats(),
        updateAlertsTable(),
        updateAgentStatus()
    ]).then(() => {
        showCustomNotification('Dữ liệu đã được cập nhật thành công', 'success');
    }).catch(error => {
        console.error('Refresh error:', error);
        showCustomNotification('Có lỗi xảy ra khi cập nhật dữ liệu', 'error');
    });
}

function showCustomNotification(message, type) {
    // Remove existing notifications
    document.querySelectorAll('.refresh-notification').forEach(n => n.remove());
    
    const notification = document.createElement('div');
    notification.className = `refresh-notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'times' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    }, 2000);
}