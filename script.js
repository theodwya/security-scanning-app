// Toggle theme between light, dark, and Heimdall mode
const themeToggle = document.getElementById('themeToggle');
themeToggle.addEventListener('change', function() {
    document.body.classList.remove('light-mode', 'dark-mode', 'heimdall-mode');
    document.body.classList.add(`${themeToggle.value}-mode`);
});

// Show/hide input fields based on the selected scan type
document.getElementById('scan_type').addEventListener('change', function() {
    document.getElementById('filesystem-options').style.display = this.value === 'filesystem' ? 'block' : 'none';
    document.getElementById('image-options').style.display = this.value === 'image' ? 'block' : 'none';
    document.getElementById('git-options').style.display = this.value === 'git' ? 'block' : 'none';
});

