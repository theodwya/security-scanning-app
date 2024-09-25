// Theme toggle
document.getElementById('themeToggle').addEventListener('click', function() {
    document.body.classList.toggle('dark-mode');
    document.body.classList.toggle('light-mode');
    this.innerHTML = document.body.classList.contains('dark-mode') ? '<i class="bi bi-sun"></i>' : '<i class="bi bi-moon"></i>';
});

// Handle tab clicks and form display
const tabs = document.querySelectorAll('.tab-link');
const contents = document.querySelectorAll('.tab-content');
const underline = document.querySelector('.tab-underline');

tabs.forEach((tab, index) => {
    tab.addEventListener('click', function(e) {
        e.preventDefault();
        
        // Remove active class from all tabs and content
        tabs.forEach(t => t.classList.remove('active'));
        contents.forEach(c => c.classList.remove('active'));

        // Add active class to clicked tab and respective content
        this.classList.add('active');
        contents[index].classList.add('active');

        // Update the underline to match the active tab's width and position
        const tabWidth = this.offsetWidth;
        const tabPosition = this.offsetLeft;
        underline.style.width = `${tabWidth}px`;
        underline.style.transform = `translateX(${tabPosition}px)`;
    });
});

// Set initial active tab and content
tabs[0].classList.add('active');
contents[0].classList.add('active');
underline.style.width = `${tabs[0].offsetWidth}px`;
underline.style.transform = `translateX(${tabs[0].offsetLeft}px)`;
