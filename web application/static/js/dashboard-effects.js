// Enhanced Dashboard Effects & Animations
class DashboardEffects {
    constructor() {
        this.init();
        this.createParticles();
        this.setupEventListeners();
    }

    init() {
        // Initialize AOS with advanced settings
        AOS.init({
            duration: 1200,
            easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
            once: true,
            offset: 50,
            delay: 100,
            anchorPlacement: 'top-bottom'
        });

        console.log('🎨 Dashboard Effects initialized');
    }

    // Create animated background particles
    createParticles() {
        const particlesContainer = document.createElement('div');
        particlesContainer.className = 'particles';
        document.body.appendChild(particlesContainer);

        for (let i = 0; i < 30; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = Math.random() * 100 + '%';
            particle.style.animationDelay = Math.random() * 15 + 's';
            particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
            particlesContainer.appendChild(particle);
        }
    }

    // Enhanced number counter with more natural animation
    animateNumbers() {
        const numbers = document.querySelectorAll('.animate-number');

        numbers.forEach(element => {
            const target = parseInt(element.textContent) || 0;
            const duration = 2000;
            const start = performance.now();

            const animate = (currentTime) => {
                const elapsed = currentTime - start;
                const progress = Math.min(elapsed / duration, 1);

                // Easing function for smoother animation
                const easeOutExpo = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
                const current = Math.floor(easeOutExpo * target);

                element.textContent = current;
                element.classList.add('number-glow');

                if (progress < 1) {
                    requestAnimationFrame(animate);
                } else {
                    // Add sparkle effect when animation completes
                    this.addSparkleEffect(element);
                }
            };

            requestAnimationFrame(animate);
        });
    }

    // Add sparkle effect to elements
    addSparkleEffect(element) {
        for (let i = 0; i < 8; i++) {
            const sparkle = document.createElement('div');
            sparkle.style.cssText = `
                position: absolute;
                width: 4px;
                height: 4px;
                background: #667eea;
                border-radius: 50%;
                pointer-events: none;
                animation: sparkle 0.8s ease-out forwards;
            `;

            const rect = element.getBoundingClientRect();
            sparkle.style.left = (rect.left + Math.random() * rect.width) + 'px';
            sparkle.style.top = (rect.top + Math.random() * rect.height) + 'px';

            document.body.appendChild(sparkle);

            setTimeout(() => sparkle.remove(), 800);
        }
    }

    // Enhanced card animations with stagger effect
    setupCardAnimations() {
        const cards = document.querySelectorAll('.card');

        cards.forEach((card, index) => {
            // Add staggered entrance animation
            setTimeout(() => {
                card.classList.add('card-animate', 'hover-lift');
            }, index * 150);

            // Add interactive hover effects
            card.addEventListener('mouseenter', () => {
                card.style.transform = 'translateY(-12px) rotateX(5deg)';
                card.style.transition = 'all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
            });

            card.addEventListener('mouseleave', () => {
                card.style.transform = 'translateY(0px) rotateX(0deg)';
            });
        });
    }

    // Loading state management
    showLoadingState(element, text = 'Đang xử lý...') {
        const originalContent = element.innerHTML;

        element.innerHTML = `
            <span class="loading-spinner me-2"></span>
            ${text}
        `;
        element.disabled = true;
        element.classList.add('loading');

        return () => {
            element.innerHTML = originalContent;
            element.disabled = false;
            element.classList.remove('loading');
        };
    }

    // Enhanced ripple effect
    createRipple(element, event) {
        const ripple = document.createElement('span');
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;

        ripple.style.cssText = `
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.6);
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            animation: rippleEffect 0.6s ease-out;
            pointer-events: none;
            z-index: 1;
        `;

        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);

        setTimeout(() => ripple.remove(), 600);
    }

    // Progressive Web App like loading indicator
    showPageLoading() {
        const loader = document.createElement('div');
        loader.innerHTML = `
            <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
                        background: rgba(102, 126, 234, 0.95); z-index: 9999; 
                        display: flex; justify-content: center; align-items: center;
                        backdrop-filter: blur(10px);" id="page-loader">
                <div style="text-align: center; color: white;">
                    <div class="loading-spinner" style="width: 60px; height: 60px; margin: 0 auto 2rem;"></div>
                    <h3 style="font-weight: 300; margin-bottom: 1rem;">Đang cập nhật dữ liệu</h3>
                    <div class="progress" style="width: 200px; height: 4px; background: rgba(255,255,255,0.3);">
                        <div class="progress-bar" style="width: 0%; background: white; transition: width 0.3s ease;" id="loading-progress"></div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(loader);

        // Simulate loading progress
        let progress = 0;
        const progressBar = document.getElementById('loading-progress');
        const interval = setInterval(() => {
            progress += Math.random() * 30;
            progressBar.style.width = Math.min(progress, 90) + '%';

            if (progress >= 90) {
                clearInterval(interval);
                setTimeout(() => {
                    progressBar.style.width = '100%';
                    setTimeout(async () => {
                        loader.remove();
                        
                        // Instead of reloading, update data via API
                        try {
                            if (window.securityDashboard && typeof window.securityDashboard.fetchDashboardStats === 'function') {
                                await window.securityDashboard.fetchDashboardStats();
                            }
                            
                            if (window.enhancedDashboard && typeof window.enhancedDashboard.fetchAndUpdateData === 'function') {
                                await window.enhancedDashboard.fetchAndUpdateData();
                            }
                        } catch (error) {
                            console.warn('Data update after loading failed:', error);
                        }
                    }, 300);
                }, 200);
            }
        }, 100);

        return loader;
    }

    // Smooth scrolling with offset
    setupSmoothScrolling() {
        const links = document.querySelectorAll('a[href^="#"]');

        links.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector(link.getAttribute('href'));

                if (target) {
                    const headerOffset = 80;
                    const elementPosition = target.getBoundingClientRect().top;
                    const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                    window.scrollTo({
                        top: offsetPosition,
                        behavior: 'smooth'
                    });
                }
            });
        });
    }

    // Silent Auto-refresh with API updates (no page reload)
    setupAutoRefresh(interval = 30000) {
        let refreshTimeout;

        const performRefresh = async () => {
            try {
                // Update dashboard statistics via API
                if (window.securityDashboard && typeof window.securityDashboard.fetchDashboardStats === 'function') {
                    await window.securityDashboard.fetchDashboardStats();
                }
                
                // Update enhanced dashboard if available
                if (window.enhancedDashboard && typeof window.enhancedDashboard.fetchAndUpdateData === 'function') {
                    await window.enhancedDashboard.fetchAndUpdateData();
                }

                // Show subtle update indicator
                this.showUpdateIndicator();
                
                console.log('Dashboard updated silently - no page reload');
            } catch (error) {
                console.warn('Silent refresh failed:', error);
                // Fallback: just update timestamp without reload
                this.updatePageTimestamp();
            }
        };

        // Show subtle update indicator
        this.showUpdateIndicator = () => {
            const indicator = document.createElement('div');
            indicator.style.cssText = `
                position: fixed;
                top: 20px;
                right: 80px;
                background: rgba(34, 197, 94, 0.9);
                color: white;
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 0.85rem;
                z-index: 1000;
                animation: slideInFromRight 0.3s ease, fadeOut 0.3s ease 2s;
                backdrop-filter: blur(10px);
            `;
            indicator.innerHTML = '<i class="fas fa-check-circle me-1"></i> Updated';
            document.body.appendChild(indicator);

            setTimeout(() => indicator.remove(), 2500);
        };

        // Update page timestamp without reload
        this.updatePageTimestamp = () => {
            const timeElement = document.getElementById('current-time');
            if (timeElement) {
                const now = new Date();
                const timeString = String(now.getHours()).padStart(2, '0') + ':' +
                    String(now.getMinutes()).padStart(2, '0') + ':' +
                    String(now.getSeconds()).padStart(2, '0');
                timeElement.textContent = timeString;
            }
        };

        // Start the refresh cycle
        const startRefreshCycle = () => {
            refreshTimeout = setTimeout(() => {
                performRefresh();
                startRefreshCycle(); // Continue the cycle
            }, interval);
        };

        startRefreshCycle();

        return {
            stop: () => clearTimeout(refreshTimeout),
            restart: () => {
                clearTimeout(refreshTimeout);
                refreshTimeout = setTimeout(performRefresh, interval);
            }
        };
    }

    // Setup all event listeners
    setupEventListeners() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupCardAnimations();
            this.animateNumbers();
            this.setupSmoothScrolling();

            // Setup button interactions
            const buttons = document.querySelectorAll('.btn:not(.no-effects)');
            buttons.forEach(button => {
                button.addEventListener('click', (e) => {
                    this.createRipple(button, e);

                    if (!button.classList.contains('no-loading')) {
                        const resetLoading = this.showLoadingState(button);
                        setTimeout(resetLoading, 1500);
                    }
                });
            });

            // Setup table row animations
            const tableRows = document.querySelectorAll('tbody tr');
            tableRows.forEach((row, index) => {
                row.style.animationDelay = `${index * 50}ms`;
                row.classList.add('fade-in');
            });

            console.log('✨ All dashboard effects activated');
        });

        // Parallax scrolling effect
        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            const parallaxElements = document.querySelectorAll('.parallax');

            parallaxElements.forEach(element => {
                const speed = element.dataset.speed || 0.5;
                element.style.transform = `translateY(${scrolled * speed}px)`;
            });
        });
    }
}

// Initialize dashboard effects
const dashboardEffects = new DashboardEffects();

// Keyframe animations for CSS injection
const additionalStyles = `
    @keyframes sparkle {
        0% { transform: scale(0) rotate(0deg); opacity: 1; }
        50% { transform: scale(1) rotate(180deg); opacity: 1; }
        100% { transform: scale(0) rotate(360deg); opacity: 0; }
    }
`;

// Inject additional styles
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalStyles;
document.head.appendChild(styleSheet);