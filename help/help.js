/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

// Accordion Toggle Logic
document.addEventListener('DOMContentLoaded', () => {
  const items = document.querySelectorAll('.accordion-item');
  const headers = document.querySelectorAll('.accordion-header');
  const searchInput = document.getElementById('help-search');

  headers.forEach(header => {
    header.addEventListener('click', () => {
      const item = header.parentElement;
      const isActive = item.classList.contains('active');

      // Close others
      items.forEach(i => i.classList.remove('active'));

      if (!isActive) item.classList.add('active');
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const term = e.target.value.toLowerCase();

      items.forEach(item => {
        const text = item.innerText.toLowerCase();
        if (text.includes(term)) {
          item.classList.remove('hidden');
        } else {
          item.classList.remove('active');
          item.classList.add('hidden');
        }
      });
    });
  }
});