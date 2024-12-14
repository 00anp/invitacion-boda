
// Configuración de la fecha objetivo (5 de abril 2025 1pm CDMX)
const targetDate = new Date('2025-04-05T13:00:00-06:00');

// Función para actualizar el countdown
function updateCountdown() {
  const currentDate = new Date();
  const difference = targetDate - currentDate;

  // Convertir la diferencia a días, horas, minutos y segundos
  const days = Math.floor(difference / (1000 * 60 * 60 * 24));
  const hours = Math.floor((difference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((difference % (1000 * 60)) / 1000);

  // Actualizar los elementos del DOM
  document.getElementById('day-box').textContent = days.toString().padStart(2, '0');
  document.getElementById('hr-box').textContent = hours.toString().padStart(2, '0');
  document.getElementById('min-box').textContent = minutes.toString().padStart(2, '0');
  document.getElementById('sec-box').textContent = seconds.toString().padStart(2, '0');
}

// Actualizar el countdown cada segundo
setInterval(updateCountdown, 1000);
updateCountdown(); // Llamada inicial

// Función genérica para manejar carruseles
function initCarousel(container) {
  const slides = container.querySelector('[data-slides]');
  let autoplayInterval;

  function moveToNextSlide() {
    const activeSlide = slides.querySelector('[data-active]');
    const slideArray = [...slides.children];
    let newIndex = slideArray.indexOf(activeSlide) + 1;
    if (newIndex >= slides.children.length) newIndex = 0;
    
    slides.children[newIndex].dataset.active = true;
    delete activeSlide.dataset.active;
  }

  function moveToPrevSlide() {
    const activeSlide = slides.querySelector('[data-active]');
    const slideArray = [...slides.children];
    let newIndex = slideArray.indexOf(activeSlide) - 1;
    if (newIndex < 0) newIndex = slides.children.length - 1;
    
    slides.children[newIndex].dataset.active = true;
    delete activeSlide.dataset.active;
  }

  function startAutoplay() {
    stopAutoplay();
    autoplayInterval = setInterval(moveToNextSlide, 3000);
  }

  function stopAutoplay() {
    if (autoplayInterval) {
      clearInterval(autoplayInterval);
    }
  }

  // Configurar botones de navegación
  const prevButton = container.querySelector('[data-carousel-button="prev"]');
  const nextButton = container.querySelector('[data-carousel-button="next"]');

  prevButton.addEventListener('click', () => {
    moveToPrevSlide();
    // Reiniciar autoplay después de navegación manual
    startAutoplay();
  });

  nextButton.addEventListener('click', () => {
    moveToNextSlide();
    // Reiniciar autoplay después de navegación manual
    startAutoplay();
  });

  // Pausar autoplay cuando el mouse está sobre el carrusel
  container.addEventListener('mouseenter', stopAutoplay);
  container.addEventListener('mouseleave', startAutoplay);

  // Iniciar autoplay
  startAutoplay();
}

// Inicializar todos los carruseles cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
  
  // Mantener el código existente para copiar CLABE
  document.querySelectorAll('.copy-btn').forEach(button => {
    button.addEventListener('click', async () => {
      const clabe = button.dataset.clabe;
      try {
        await navigator.clipboard.writeText(clabe);
        button.classList.add('copied');
        button.innerHTML = '<i class="fa-solid fa-check"></i>';
        
        setTimeout(() => {
          button.classList.remove('copied');
          button.innerHTML = '<i class="fa-regular fa-copy"></i>';
        }, 2000);
      } catch (err) {
        console.error('Error al copiar:', err);
      }
    });
  });

  // Inicializar todos los carruseles
  document.querySelectorAll('[data-carousel]').forEach(carousel => {
    initCarousel(carousel);
  });
});