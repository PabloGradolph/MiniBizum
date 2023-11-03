function toggleDescription(element) {
    const fullDescription = element.querySelector(".full-description");
    if (fullDescription.style.display === "block") {
        fullDescription.style.display = "none";
    } else {
        fullDescription.style.display = "block";
    }
}

function setupExpandableDescriptions() {
    const historyDiv = document.querySelector("#history");
    const missionDiv = document.querySelector("#mission");

    const isSmallScreen = window.innerWidth < 720;

    if (isSmallScreen) {
        historyDiv.addEventListener("click", function(event) {
            toggleDescription(historyDiv);
        });
        missionDiv.addEventListener("click", function(event) {
            toggleDescription(missionDiv);
        });
    } else {
        // En pantallas grandes, mostramos ambas descripciones completas y quitamos los event listeners
        const historyFullDescription = historyDiv.querySelector(".full-description");
        historyFullDescription.style.display = "block";
        const missionFullDescription = missionDiv.querySelector("#mission-full-description");
        missionFullDescription.style.display = "block";
    }
}

document.addEventListener("DOMContentLoaded", setupExpandableDescriptions);
window.addEventListener("resize", setupExpandableDescriptions);