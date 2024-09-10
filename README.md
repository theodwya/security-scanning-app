Sec-scanner/
│
├── app.py                     # Main Flask application file
│
├── Dockerfile                 # Docker configuration for building the image
│
├── requirements.txt           # Python dependencies
│
├── templates/                 # HTML templates for Flask
│   ├── index.html             # Main HTML file with the form and scan results
│   ├── review.html            # HTML for the review page
│   ├── about.html             # About page content (if separated)
│   └── how_to.html            # How-To page content (if separated)
│
├── static/                    # Static files like CSS, JavaScript, images
│   ├── style.css              # Custom styles for the application
│   ├── script.js              # Custom JavaScript for client-side logic
│   └── images/                # Images used in the application (if any)
│
├── uploads/                   # Directory for uploaded files
│   └── ...                    # Files uploaded by users
│
└── scan-results/              # Directory for storing scan results
    ├── clamav_scan.log        # Example scan result file for ClamAV
    ├── trivy_fs_scan.json     # Example scan result for Trivy filesystem scan
    ├── trivy_image_scan.json  # Example scan result for Trivy image scan
    └── review.json            # JSON file storing review data



