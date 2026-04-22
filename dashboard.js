document.addEventListener('DOMContentLoaded', () => {
    const chartContainer = document.getElementById('chart-container');

    async function fetchResults() {
        try {
            // Add a cache buster to prevent stale data
            const response = await fetch(`results.json?t=${new Date().getTime()}`);
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            const data = await response.json();
            renderChart(data);
        } catch (error) {
            chartContainer.innerHTML = `
                <div class="loading-state" style="color: var(--danger);">
                    Error loading results.json. Ensure analyzer.exe has been run and a local server is hosting the files.
                </div>
            `;
            console.error('Error fetching data:', error);
        }
    }

    function renderChart(data) {
        chartContainer.innerHTML = ''; // Clear loading state

        if (!data || data.length === 0) {
            chartContainer.innerHTML = '<div class="loading-state">No malicious IPs found.</div>';
            return;
        }

        // Find max errors to calculate percentages
        const maxErrors = Math.max(...data.map(item => item.errors));

        data.forEach((item, index) => {
            const percentage = (item.errors / maxErrors) * 100;
            const delay = index * 0.1; // Stagger animation

            const barItem = document.createElement('div');
            barItem.className = 'bar-item';
            barItem.style.animationDelay = `${delay}s`;

            barItem.innerHTML = `
                <div class="ip-label">${item.ip}</div>
                <div class="bar-wrapper">
                    <div class="bar-fill" style="width: 0%; transition-delay: ${delay + 0.3}s"></div>
                </div>
                <div class="error-count">${item.errors.toLocaleString()} errors</div>
            `;

            chartContainer.appendChild(barItem);

            // Trigger animation after DOM insertion
            setTimeout(() => {
                const fill = barItem.querySelector('.bar-fill');
                fill.style.width = `${Math.max(percentage, 2)}%`; // Minimum 2% width for visibility
            }, 50);
        });
    }

    fetchResults();
});
