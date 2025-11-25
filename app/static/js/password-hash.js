async function hashText(value) {
    const encoder = new TextEncoder();
    const data = encoder.encode(value);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function isHexDigest(value) {
    return /^[a-f0-9]{64}$/i.test(value.trim());
}

const PASSWORD_POLICY_REGEX = /^(?=.*[A-Z])(?=.*[^A-Za-z0-9]).{8,}$/;
const PASSWORD_POLICY_MESSAGE = 'Password must be at least 8 characters long, include one uppercase letter, and one special character.';

function initPasswordToggles() {
    const passwordInputs = document.querySelectorAll('input[data-password-field="true"]');

    passwordInputs.forEach(input => {
        if (input.dataset.toggleReady === 'true') {
            return;
        }
        input.dataset.toggleReady = 'true';

        const wrapper = document.createElement('div');
        wrapper.className = 'password-input-wrapper';
        const parent = input.parentNode;
        parent.insertBefore(wrapper, input);
        wrapper.appendChild(input);

        const toggleBtn = document.createElement('button');
        toggleBtn.type = 'button';
        toggleBtn.className = 'password-toggle-btn';
        toggleBtn.setAttribute('aria-label', 'Show password');

        const icon = document.createElement('i');
        icon.className = 'fas fa-eye';
        toggleBtn.appendChild(icon);

        toggleBtn.addEventListener('click', () => {
            const shouldShow = input.type === 'password';
            input.type = shouldShow ? 'text' : 'password';
            toggleBtn.setAttribute('aria-label', shouldShow ? 'Hide password' : 'Show password');
            toggleBtn.classList.toggle('is-visible', shouldShow);
            icon.classList.toggle('fa-eye', !shouldShow);
            icon.classList.toggle('fa-eye-slash', shouldShow);
        });

        wrapper.appendChild(toggleBtn);
    });
}

function maskPasswordInput(input) {
    input.type = 'password';
    const parent = input.parentElement;
    if (!parent) {
        return;
    }
    const toggleBtn = parent.querySelector('.password-toggle-btn');
    if (toggleBtn) {
        toggleBtn.classList.remove('is-visible');
        toggleBtn.setAttribute('aria-label', 'Show password');
        const icon = toggleBtn.querySelector('i');
        if (icon) {
            icon.classList.add('fa-eye');
            icon.classList.remove('fa-eye-slash');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initPasswordToggles();
    const forms = document.querySelectorAll('form[data-hash-password="true"]');

    forms.forEach(form => {
        form.addEventListener('submit', async event => {
            if (form.dataset.hashing === 'true') {
                return;
            }

            const passwordInputs = Array.from(form.querySelectorAll('input[data-password-field="true"]'));
            if (!passwordInputs.length) {
                return;
            }

            const inputsToHash = passwordInputs.filter(input => input.value && !isHexDigest(input.value));
            if (!inputsToHash.length) {
                return;
            }

            for (const input of inputsToHash) {
                if (!PASSWORD_POLICY_REGEX.test(input.value)) {
                    input.setCustomValidity(PASSWORD_POLICY_MESSAGE);
                    input.reportValidity();
                    input.setCustomValidity('');
                    return;
                }
            }

            event.preventDefault();
            form.dataset.hashing = 'true';

            try {
                for (const input of inputsToHash) {
                    maskPasswordInput(input);
                    const hashed = await hashText(input.value);
                    input.value = hashed;
                }
            } catch (error) {
                console.error('Unable to hash password on client:', error);
                delete form.dataset.hashing;
                return;
            }

            form.submit();
        }); 
    });
});
