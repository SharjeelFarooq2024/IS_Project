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

document.addEventListener('DOMContentLoaded', () => {
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

            event.preventDefault();
            form.dataset.hashing = 'true';

            try {
                for (const input of inputsToHash) {
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
