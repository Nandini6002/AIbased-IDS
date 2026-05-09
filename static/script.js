// Fetch dashboard stats every 2 seconds

async function fetchStats(){

    try{

        const response = await fetch('/stats');

        const data = await response.json();

        // Update counters
        const normal = document.getElementById("normal");
        const attacks = document.getElementById("attacks");

        if(normal){
            normal.innerText = data.normal;
        }

        if(attacks){
            attacks.innerText = data.attacks;
        }

        // Update logs
        const logs = document.getElementById("logs");

        if(logs){

            logs.innerHTML = "";

            data.logs.reverse().forEach(log => {

                let li = document.createElement("li");

                li.innerText = log;

                if(log.includes("Attack")){
                    li.style.borderLeft = "5px solid red";
                }
                else{
                    li.style.borderLeft = "5px solid #00ff99";
                }

                logs.appendChild(li);

            });
        }

        // Update chart if exists
        if(window.attackChart){

            window.attackChart.data.datasets[0].data = [
                data.normal,
                data.attacks
            ];

            window.attackChart.update();
        }

    }

    catch(error){

        console.log("Error fetching stats:", error);

    }
}

// Auto refresh every 2 sec
setInterval(fetchStats, 2000);

// Initial fetch
fetchStats();


// Theme toggle feature

function toggleTheme(){

    document.body.classList.toggle("light-mode");

}


// Fake notification popup

function showNotification(message){

    const notification = document.createElement("div");

    notification.innerText = message;

    notification.style.position = "fixed";
    notification.style.top = "20px";
    notification.style.right = "20px";

    notification.style.background = "#ff4d4d";
    notification.style.color = "white";

    notification.style.padding = "15px";

    notification.style.borderRadius = "10px";

    notification.style.boxShadow = "0 0 10px red";

    notification.style.zIndex = "1000";

    document.body.appendChild(notification);

    setTimeout(() => {

        notification.remove();

    }, 3000);
}


// Example alert
// showNotification("⚠ Attack Detected");