// Wait for the DOM to load
document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector(".registration-form");

    form.addEventListener("submit", (event) => {
        // Prevent form submission
        event.preventDefault();

        // Validate form fields
        const name = document.getElementById("name").value.trim();
        const category = document.getElementById("userType").value;
        const nic = document.getElementById("nic").value.trim();
        const email = document.getElementById("email").value.trim();
        const mobile = document.getElementById("mobile").value.trim();
        const password = document.getElementById("password").value.trim();

        let isValid = true;

        // Validate Name
        if (name === "") {
            alert("Name is required.");
            isValid = false;
        }

        // Validate userType
        if (userType === "") {
            alert("Please select a participation category.");
            isValid = false;
        }

        // Validate NIC/Passport No
        if (!/^[A-Z0-9]{5,20}$/i.test(nic)) {
            alert("NIC/Passport No should be alphanumeric and 5-20 characters long.");
            isValid = false;
        }

        // Validate Email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            alert("Please enter a valid email address.");
            isValid = false;
        }

        // Validate Mobile Number
        if (!/^\d{10}$/.test(mobile)) {
            alert("Mobile number must be exactly 10 digits.");
            isValid = false;
        }

        // Validate Password
        if (password.length < 6) {
            alert("Password must be at least 6 characters long.");
            isValid = false;
        }

        // If all fields are valid, submit the form
        if (isValid) {
            alert("Form submitted successfully!");
            form.submit(); // Uncomment this to enable form submission
        }
    });
});
