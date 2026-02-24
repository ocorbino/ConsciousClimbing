const weatherStatus = document.getElementById("weather-status");
const carousel = document.querySelector(".carousel");

if (weatherStatus) {
  const weatherCodes = {
    0: "Clear sky",
    1: "Mostly clear",
    2: "Partly cloudy",
    3: "Overcast",
    45: "Fog",
    48: "Rime fog",
    51: "Light drizzle",
    53: "Drizzle",
    55: "Dense drizzle",
    61: "Light rain",
    63: "Rain",
    65: "Heavy rain",
    71: "Light snow",
    73: "Snow",
    75: "Heavy snow",
    80: "Rain showers",
    81: "Rain showers",
    82: "Heavy rain showers",
    95: "Thunderstorm"
  };

  fetch(
    "https://api.open-meteo.com/v1/forecast?latitude=44.911&longitude=-116.098&current=temperature_2m,apparent_temperature,weather_code,wind_speed_10m&temperature_unit=fahrenheit&wind_speed_unit=mph&timezone=America%2FBoise"
  )
    .then((response) => response.json())
    .then((data) => {
      if (!data.current) {
        throw new Error("No weather data available");
      }

      const current = data.current;
      const summary = weatherCodes[current.weather_code] || "Current conditions";
      const timestamp = new Date(current.time).toLocaleString("en-US", {
        dateStyle: "medium",
        timeStyle: "short"
      });

      weatherStatus.textContent = `${summary} • ${Math.round(current.temperature_2m)}F (feels like ${Math.round(
        current.apparent_temperature
      )}F) • Wind ${Math.round(current.wind_speed_10m)} mph • Updated ${timestamp}`;
    })
    .catch(() => {
      weatherStatus.textContent =
        "Weather data is temporarily unavailable. Please check a local weather source for current McCall conditions.";
    });
}

if (carousel) {
  const slides = Array.from(carousel.querySelectorAll(".carousel-slide"));
  const prevBtn = carousel.querySelector(".carousel-btn.prev");
  const nextBtn = carousel.querySelector(".carousel-btn.next");
  let current = slides.findIndex((slide) => slide.classList.contains("is-active"));
  current = current >= 0 ? current : 0;

  const setSlide = (index) => {
    slides[current].classList.remove("is-active");
    current = (index + slides.length) % slides.length;
    slides[current].classList.add("is-active");
  };

  const nextSlide = () => setSlide(current + 1);
  const prevSlide = () => setSlide(current - 1);

  nextBtn?.addEventListener("click", nextSlide);
  prevBtn?.addEventListener("click", prevSlide);

  // Constant loop autoplay.
  setInterval(nextSlide, 3200);
}
