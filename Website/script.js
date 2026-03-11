document.addEventListener("DOMContentLoaded", () => {
    
    // ==========================================================================
    // 1. Huly.io Intersection Observer (Reveal Physics)
    // ==========================================================================
    // Elements start at translateY(40) scale(0.95) and animate to translateY(0) scale(1)
    
    const revealElements = document.querySelectorAll('.reveal-up, .reveal-text');
    
    const revealOptions = {
        threshold: 0.1,
        rootMargin: "0px 0px -50px 0px" // Trigger slightly before it comes fully into view
    };

    const revealObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Add the active class to trigger the CSS transition
                entry.target.classList.add('active');
                // Unobserve after revealing once
                observer.unobserve(entry.target);
            }
        });
    }, revealOptions);

    revealElements.forEach(el => {
        revealObserver.observe(el);
    });

    // ==========================================================================
    // 2. 3D Floating Mockup Parallax (Hero Section)
    // ==========================================================================
    
    const heroMockup = document.getElementById('parallax-mockup');
    const heroSection = document.querySelector('.huly-hero');

    if (heroMockup && heroSection && window.innerWidth > 768) {
        
        heroSection.addEventListener('mousemove', (e) => {
            const rect = heroSection.getBoundingClientRect();
            
            // Calculate mouse position relative to the center of the hero section (-1 to 1)
            const x = (e.clientX - rect.left - rect.width / 2) / (rect.width / 2);
            const y = (e.clientY - rect.top - rect.height / 2) / (rect.height / 2);
            
            // Limit the tilt angles (e.g., max 10 degrees)
            const rotateX = y * -6 + 8; // The +8 maintains the default tilt we set in CSS
            const rotateY = x * 6;
            
            // Apply the transform
            heroMockup.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        });

        // Smoothly snap back to resting state when mouse leaves
        heroSection.addEventListener('mouseleave', () => {
            heroMockup.style.transition = 'transform 0.5s ease-out';
            heroMockup.style.transform = `rotateX(8deg) rotateY(0deg)`;
            
            // Remove transition after snap-back so mouse tracking is immediate again
            setTimeout(() => {
                heroMockup.style.transition = 'transform 0.1s ease-out';
            }, 500);
        });
    }

});
