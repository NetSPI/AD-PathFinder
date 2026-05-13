const TooltipManager = {
    tooltip: null,
    scrollInterval: null,
    scrollDirection: 1,
    scrollSpeed: 0.5,
    scrollTimeout: null,

    init() {
        this.tooltip = document.createElement('div');
        this.tooltip.id = 'user-tooltip';
        this.tooltip.style.position = 'fixed';
        this.tooltip.style.display = 'none';
        this.tooltip.style.backgroundColor = 'white';
        this.tooltip.style.border = '1px solid black';
        this.tooltip.style.padding = '10px';
        this.tooltip.style.zIndex = '1000';
        this.tooltip.style.maxHeight = '70vh';
        this.tooltip.style.overflowY = 'hidden';
        document.body.appendChild(this.tooltip);

        this.setupEventListeners();
    },

    setupEventListeners() {
        document.body.addEventListener('mouseover', e => {
            const hoverableElement = this.findHoverableParent(e.target);
            if (hoverableElement) {
                const content = this.getTooltipContent(hoverableElement);
                if (content) {
                    this.show(e, content);
                    this.scrollTimeout = setTimeout(() => {
                        this.startScrolling();
                    }, 3000);
                }
            }
        });

        document.body.addEventListener('mouseout', e => {
            const hoverableElement = this.findHoverableParent(e.target);
            if (hoverableElement) {
                if (this.scrollTimeout) {
                    clearTimeout(this.scrollTimeout);
                    this.scrollTimeout = null;
                }
                this.tooltip.scrollTop = 0;
                this.stopScrolling();
                this.hide();
            }
        });

        document.body.addEventListener('mousemove', e => {
            const hoverableElement = this.findHoverableParent(e.target);
            if (hoverableElement) {
                this.position(e);
            }
        });
    },

    findHoverableParent(element) {
        // Walk up the DOM tree to find an element with 'hoverable-username' class
        let current = element;
        while (current && current !== document.body) {
            if (current.classList && current.classList.contains('hoverable-username')) {
                return current;
            }
            current = current.parentElement;
        }
        return null;
    },

    getTooltipContent(element) {
        const staticContent = element.getAttribute('data-tooltip');
        if (staticContent) return staticContent;

        const username = element.getAttribute('data-username');
        if (username) return generateTooltip(username);

        return '';
    },

    show(e, content) {
        this.tooltip.innerHTML = content;
        this.tooltip.style.display = 'block';
        this.position(e);
    },

    hide() {
        this.tooltip.style.display = 'none';
    },

    position(e) {
        const padding = 10;
        const tooltipWidth = this.tooltip.offsetWidth;
        const tooltipHeight = Math.min(this.tooltip.scrollHeight, window.innerHeight * 0.7);
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        let x = e.clientX + padding;
        let y = e.clientY + padding;

        if (x + tooltipWidth > viewportWidth) {
            x = e.clientX - tooltipWidth - padding;
        }

        if (y + tooltipHeight > viewportHeight) {
            y = viewportHeight - tooltipHeight - padding;
        }

        x = Math.max(0, x);
        y = Math.max(0, y);

        this.tooltip.style.left = x + 'px';
        this.tooltip.style.top = y + 'px';
    },

    startScrolling() {
        const tooltipHeight = this.tooltip.offsetHeight;
        const contentHeight = this.tooltip.scrollHeight;
        
        if (contentHeight > tooltipHeight) {
            this.scrollInterval = setInterval(() => {
                const currentScroll = this.tooltip.scrollTop;
                const maxScroll = contentHeight - tooltipHeight;

                if (currentScroll >= maxScroll) {
                    this.scrollDirection = -1;
                } else if (currentScroll <= 0) {
                    this.scrollDirection = 1;
                }

                this.tooltip.scrollTop += this.scrollDirection * this.scrollSpeed;
            }, 16);
        }
    },

    stopScrolling() {
        if (this.scrollInterval) {
            clearInterval(this.scrollInterval);
            this.scrollInterval = null;
        }
        this.tooltip.scrollTop = 0;
    }
};

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById("defaultOpen").click();
    TooltipManager.init();
    generateAccountCharts();
    setupPasswordLengthChart();
    
});

let previousTab = null;
let previousSection = null;
let previousScrollPosition = undefined;
let previousTabContentId = null;

function openTab(evt, tabName, fromNavigation = false) {
    const tabcontent = document.getElementsByClassName("tabcontent");
    const tablinks = document.getElementsByClassName("tablinks");
    
    Array.from(tabcontent).forEach(tab => tab.style.display = "none");
    Array.from(tablinks).forEach(link => link.className = link.className.replace(" active", ""));
    
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
    
    // Only clear previous values if this is a direct user click, not from navigation
    if (!fromNavigation) {
        previousTab = null;
        previousSection = null;
        previousScrollPosition = undefined;
        previousTabContentId = null;
        document.getElementById('backButton').style.display = 'none';
    }
}

function goBack() {
    if (previousTab && typeof previousScrollPosition !== 'undefined') {
        console.log('Going back to:', {
            previousTab: previousTab,
            previousScrollPosition: previousScrollPosition,
            previousTabContentId: previousTabContentId
        });
        
        // Find and click the correct tab button
        const tabButton = Array.from(document.getElementsByClassName('tablinks'))
            .find(btn => btn.textContent.trim() === previousTab);
        
        if (tabButton) {
            // Use openTab with fromNavigation=true to prevent clearing variables
            const clickEvent = { currentTarget: tabButton };
            openTab(clickEvent, previousTabContentId || 'PolicyCompliance', true);
            
            // Wait for tab content to be displayed, then restore scroll position
            setTimeout(() => {
                console.log('Restoring scroll position to:', previousScrollPosition);
                window.scrollTo({
                    top: previousScrollPosition,
                    behavior: 'smooth'
                });
                
                // Clear the navigation state after restoring
                setTimeout(() => {
                    previousTab = null;
                    previousSection = null;
                    previousScrollPosition = undefined;
                    previousTabContentId = null;
                    document.getElementById('backButton').style.display = 'none';
                }, 100);
            }, 150);
        }
    }
}

function generateAccountCharts() {
    generateChart('userChart', `User Accounts - ${domainName}`, [
        stats.total_users,
        stats.enabled_users,
        stats.disabled_users,
        stats.cracked_users
    ], stats.enabled_users);

    generateChart('computerChart', `Computer Accounts - ${domainName}`, [
        stats.total_computers,
        stats.enabled_computers,
        stats.disabled_computers,
        stats.cracked_computers
    ], stats.enabled_computers);
}

function generateChart(canvasId, label, data, enabledCount) {
    const ctx = document.getElementById(canvasId).getContext("2d");
    new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Total", "Enabled", "Disabled", "Cracked"],
            datasets: [{
                label: label,
                data: data,
                backgroundColor: [
                    "rgba(30, 64, 175, 0.6)",   // Dark Blue (#1E40AF) - Total accounts
                    "rgba(16, 185, 129, 0.6)",  // Green (#10B981) - Enabled
                    "rgba(107, 114, 128, 0.6)", // Grey (#6B7280) - Disabled
                    "rgba(220, 38, 38, 0.6)"    // Strong Red (#DC2626) - Cracked
                ],
                borderColor: [
                    "rgba(30, 64, 175, 1)",   // Dark Blue (#1E40AF) - Total accounts
                    "rgba(16, 185, 129, 1)",  // Green (#10B981) - Enabled
                    "rgba(107, 114, 128, 1)", // Grey (#6B7280) - Disabled
                    "rgba(220, 38, 38, 1)"    // Strong Red (#DC2626) - Cracked
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true }
            },
            onClick: function(evt, elements) {
                if (elements.length > 0 && elements[0].index === 3) {
                    scrollToWeakPasswords();
                }
            },
            plugins: {
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) label += ': ';
                            if (context.parsed.y !== null) {
                                label += context.parsed.y;
                                if (context.label === "Cracked") {
                                    let percentage = (context.parsed.y / enabledCount * 100).toFixed(2);
                                    label += ` (${percentage}% of enabled)`;
                                }
                            }
                            return label;
                        }
                    }
                }
            },
            onHover: (event, chartElement) => {
                event.native.target.style.cursor = chartElement[0] ? 'pointer' : 'default';
            }
        }
    });
}

function setupPasswordLengthChart() {
    const lengthCtx = document.getElementById("lengthChart");
    if (!lengthCtx) {
        console.error("Cannot find canvas element for lengthChart");
        return;
    }

    const minPasswordLength = domainPolicy && domainPolicy.minpwdlength ? domainPolicy.minpwdlength : null;
    const labels = Object.keys(passwordLengthData);
    const data = Object.values(passwordLengthData).map(users => users.length);
    
    // Create colors based on whether length meets minimum requirement (if known)
    const backgroundColors = labels.map(length => {
        if (minPasswordLength === null) {
            return "rgba(54, 162, 235, 0.6)"; // Default blue when no policy known
        }
        return parseInt(length) < minPasswordLength ? 
            "rgba(220, 53, 69, 0.6)" : // Red for below minimum
            "rgba(54, 162, 235, 0.6)"; // Blue for meets/exceeds minimum
    });
    
    const borderColors = labels.map(length => {
        if (minPasswordLength === null) {
            return "rgba(54, 162, 235, 1)"; // Default blue when no policy known
        }
        return parseInt(length) < minPasswordLength ? 
            "rgba(220, 53, 69, 1)" : // Red for below minimum
            "rgba(54, 162, 235, 1)"; // Blue for meets/exceeds minimum
    });

    const lengthData = {
        labels: labels,
        datasets: [{
            label: "Number of Users",
            data: data,
            backgroundColor: backgroundColors,
            borderColor: borderColors,
            borderWidth: 1
        }]
    };

    new Chart(lengthCtx, {
        type: "bar",
        data: lengthData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: "Password Length"
                    }
                },
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: "Number of Users"
                    }
                }
            },
            plugins: {
                legend: {
                    display: false // We'll create custom legend
                },
                title: {
                    display: true,
                    text: `Password Length Distribution - ${domainName}`
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function(context) {
                            const length = parseInt(context.label);
                            const count = context.parsed.y;
                            let status = '';
                            if (minPasswordLength !== null) {
                                status = length < minPasswordLength ? ' (Below minimum)' : ' (Meets requirement)';
                            }
                            return `Users: ${count}${status}`;
                        }
                    }
                }
            },
            onClick: function(_, elements) {
                if (elements && elements.length > 0) {
                    updateUserList(this.data.labels[elements[0].index]);
                }
            },
            onHover: (event, chartElement) => {
                event.native.target.style.cursor = chartElement[0] ? 'pointer' : 'default';
            }
        }
    });

    if (lengthData.labels.length > 0) {
        updateUserList(lengthData.labels[0]);
    }
}

function updateUserList(length) {
    const users = passwordLengthData[length] || [];
    const userListContainer = document.getElementById("userListContainer");
    const userListTitle = document.getElementById("userListTitle");
    const userList = document.getElementById("userList");
    
    if (!userListContainer || !userListTitle || !userList) {
        console.error("Cannot find elements for user list display");
        return;
    }

    userList.innerHTML = "";
    userListContainer.style.display = "block";

    if (users.length === 0) {
        userListTitle.textContent = `No users found with password length ${length}.`;
        return;
    }

    userListTitle.textContent = `Users with password length ${length}:`;
    users.forEach(user => {
        const li = document.createElement("li");
        if (outputFormat === "unsafe" && typeof user === "string" && user.includes(":")) {
            const [username, ...passwordParts] = user.split(":");
            const password = passwordParts.join(":").replace(/:$/, '');
            const passwordDisplay = password === '' ? '(blank)' : password;
            li.innerHTML = `<span class="hoverable-username" data-username="${escapeHtml(username.toLowerCase())}">${escapeHtml(username)}</span>: <span class="password">${escapeHtml(passwordDisplay)}</span>`;
        } else {
            // In safe mode or if no colon separator, only display username (strip any potential password data)
            const cleanUser = typeof user === "string" && user.includes(":") ? user.split(":")[0] : user;
            li.innerHTML = `<span class="hoverable-username" data-username="${escapeHtml(String(cleanUser).toLowerCase())}">${escapeHtml(cleanUser)}</span>`;
        }
        userList.appendChild(li);
    });
}

function scrollToWeakPasswords() {
    const weakPasswordsSection = document.getElementById('weak_passwords-section');
    if (weakPasswordsSection) {
        weakPasswordsSection.scrollIntoView({ behavior: 'smooth' });
    }
}

function escapeHtml(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

function generateTooltip(username) {
    const userDetail = userDetails[String(username || '').toLowerCase()];
    if (!userDetail) return '';

    const groups = Array.isArray(userDetail.groups) ? userDetail.groups : [];
    const sharedWith = Array.isArray(userDetail.sharedWith) ? userDetail.sharedWith : [];

    const renderGroup = name => {
        const escaped = escapeHtml(name);
        const upper = String(name || '').toUpperCase();
        return highValueGroupsList.some(hvg => upper.includes(hvg))
            ? `<strong>${escaped}</strong>`
            : escaped;
    };

    let content = `
        <div style="min-width: 300px;">
            <strong>Domain:</strong> ${escapeHtml(userDetail.domain || 'N/A')}<br>
            <strong>Username:</strong> ${escapeHtml(userDetail.username)}<br>
            <strong>Description:</strong> ${escapeHtml(userDetail.description)}<br>
            <strong>Enabled:</strong> ${userDetail.enabled ? 'Yes' : 'No'}<br>
            <strong>Admin:</strong> ${userDetail.isAdmin ? 'Yes' : 'No'}<br>
            <strong>Privileged:</strong> ${userDetail.isPrivileged ? 'Yes' : 'No'}<br>
    `;

    if (outputFormat === 'unsafe' && (userDetail.isAdmin || userDetail.isPrivileged)) {
        content += `<strong>Privileged Access:</strong> ${escapeHtml(userDetail.adminAccessReason || 'N/A')}<br>`;
    }

    content += `
            <strong>Last Logon:</strong> ${escapeHtml(formatTimestamp(userDetail.lastLogon))}<br>
            <strong>Password Last Changed:</strong> ${escapeHtml(formatTimestamp(userDetail.passwordLastChanged))}<br>
            <strong>Groups:</strong> ${groups.map(renderGroup).join(', ')}
        </div>
    `;

    if (sharedWith.length > 0) {
        content += `<br><strong>Shared with:</strong> ${sharedWith.map(escapeHtml).join(', ')}`;
    }

    if (outputFormat === 'unsafe') {
        let pwdDisplay;
        if (userDetail.password === '') pwdDisplay = '(blank)';
        else if (userDetail.password == null) pwdDisplay = 'Not cracked';
        else pwdDisplay = userDetail.password;
        content += `<br><strong>Password:</strong> ${escapeHtml(pwdDisplay)}`;
    }

    return content;
}

function formatTimestamp(timestamp) {
    if (timestamp === 'Never' || timestamp === 'Unknown') return timestamp;
    return new Date(timestamp * 1000).toLocaleString();
}


function switchToPasswordAudit() {
    const passwordAuditButton = Array.from(document.getElementsByClassName("tablinks"))
        .find(button => button.textContent === "Password Audit");
    if (passwordAuditButton) {
        passwordAuditButton.click();
    }
}

function navigateToSection(tabName, sectionId, categoryText) {
    const currentActive = document.querySelector('.tablinks.active');
    
    if (currentActive) {
        // Store the current tab name
        previousTab = currentActive.textContent.trim();
        
        // Store the current scroll position BEFORE any navigation
        previousScrollPosition = window.pageYOffset || document.documentElement.scrollTop;
        
        // Store current tab content ID for more reliable restoration
        const currentTabContent = document.querySelector('.tabcontent[style*="block"]');
        if (currentTabContent) {
            previousTabContentId = currentTabContent.id;
        }
        
        console.log('Storing navigation context:', {
            previousTab: previousTab,
            previousScrollPosition: previousScrollPosition,
            previousTabContentId: previousTabContentId
        });
    }
    
    const targetButton = Array.from(document.getElementsByClassName('tablinks'))
        .find(btn => btn.textContent === tabName);
    
    // Manually switch tabs without clearing previous values
    if (targetButton) {
        const tabcontent = document.getElementsByClassName("tabcontent");
        const tablinks = document.getElementsByClassName("tablinks");
        
        Array.from(tabcontent).forEach(tab => tab.style.display = "none");
        Array.from(tablinks).forEach(link => link.className = link.className.replace(" active", ""));
        
        // Extract tab name from onclick attribute
        const onclickAttr = targetButton.getAttribute('onclick');
        const tabNameMatch = onclickAttr.match(/openTab\(event,\s*'([^']+)'\)/);
        if (tabNameMatch) {
            const targetTabName = tabNameMatch[1];
            document.getElementById(targetTabName).style.display = "block";
            targetButton.className += " active";
        }
    }
    
    setTimeout(() => {
        let targetSection = null;
        
        // If we have categoryText, find the specific section with that category
        if (categoryText) {
            const sections = document.querySelectorAll(`[id="${sectionId}"]`);
            for (const section of sections) {
                const heading = section.querySelector('h2');
                if (heading && heading.textContent.includes(`containing '${categoryText}'`)) {
                    targetSection = section;
                    break;
                }
            }
        }
        
        // Fall back to first section with that ID if no specific category found
        if (!targetSection) {
            targetSection = document.getElementById(sectionId);
        }
        
        if (targetSection) {
            targetSection.scrollIntoView({ behavior: 'smooth' });
            targetSection.style.backgroundColor = '#fff3cd';
            setTimeout(() => targetSection.style.backgroundColor = '', 2000);
        }
    }, 100);
    
    document.getElementById('backButton').style.display = 'block';
}

function downloadPolicyViolationsCSV() {
    const headers = Object.keys(policyViolationsData[0]);
    let csv = headers.join(',') + '\n';
    
    policyViolationsData.forEach(row => {
        csv += headers.map(h => {
            const val = String(row[h]);
            return val.includes(',') ? `"${val}"` : val;
        }).join(',') + '\n';
    });
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${domainName}.passwordaudit.csv`;
    link.click();
}
