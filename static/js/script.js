/**
 * ZeroTrace — Login After Dark
 * Interactive telemetry, live clocks, and client-side alert filters
 */

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initAlertFilters();
  initTimeRangeSelector();
  initMobileDrawer();
});

/**
 * Real-time Clock & Date Formatter
 */
function initClock() {
  const clockEl = document.getElementById('live-clock');
  const dateEl = document.getElementById('live-date');

  function updateClock() {
    const now = new Date();
    if (clockEl) {
      clockEl.textContent = now.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }) + ' UTC';
    }
    if (dateEl) {
      dateEl.textContent = now.toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric'
      });
    }
  }

  updateClock();
  setInterval(updateClock, 1000);
}

/**
 * Client-side Search and Severity Filter for Alerts Table
 */
function initAlertFilters() {
  const searchInput = document.getElementById('alertSearch');
  const filterButtons = document.querySelectorAll('#severityFilter .filter-btn');
  const alertRows = document.querySelectorAll('#alertsTable tbody .alert-row');

  if (!alertRows.length) return;

  let currentSeverity = 'all';
  let searchQuery = '';

  function applyFilter() {
    alertRows.forEach(row => {
      const severity = (row.getAttribute('data-severity') || '').toLowerCase();
      const textContent = row.textContent.toLowerCase();

      const matchesSeverity = (currentSeverity === 'all') || (severity === currentSeverity);
      const matchesSearch = !searchQuery || textContent.includes(searchQuery);

      if (matchesSeverity && matchesSearch) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.trim().toLowerCase();
      applyFilter();
    });
  }

  if (filterButtons.length) {
    filterButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        filterButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentSeverity = btn.getAttribute('data-filter') || 'all';
        applyFilter();
      });
    });
  }
}

/**
 * Time Window Range Selector Pill Buttons
 */
function initTimeRangeSelector() {
  const pills = document.querySelectorAll('.time-range-group .pill-btn');
  pills.forEach(pill => {
    pill.addEventListener('click', () => {
      pills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
    });
  });
}

/**
 * Responsive Mobile Drawer Toggle
 */
function initMobileDrawer() {
  const menuBtn = document.getElementById('mobileMenuBtn');
  const sidebar = document.getElementById('sidebar');

  if (menuBtn && sidebar) {
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      sidebar.classList.toggle('open');
    });

    document.addEventListener('click', (e) => {
      if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && e.target !== menuBtn) {
        sidebar.classList.remove('open');
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && sidebar.classList.contains('open')) {
        sidebar.classList.remove('open');
      }
    });
  }
}

/**
 * Incident Form Handler (Contact Page)
 */
window.handleIncidentSubmit = function() {
  const statusMsg = document.getElementById('formStatusMsg');
  const form = document.getElementById('incidentForm');
  if (statusMsg) {
    const ticketId = 'INC-' + Math.floor(10000 + Math.random() * 90000);
    statusMsg.textContent = `✓ Ticket ${ticketId} dispatched to SOC Commander. Response SLA engaged.`;
    statusMsg.style.display = 'inline-block';
    if (form) form.reset();

    setTimeout(() => {
      statusMsg.textContent = '';
    }, 6000);
  }
};
setInterval(tick, 1000);