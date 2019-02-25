$(document).ready(function(){
    $('body').on('mouseover touchstart','#homenav li',function(){
        $(this).find('.logo img').removeClass('grayscale');
    });
    $('body').on('mouseout touchend','#homenav li',function(){
        $(this).find('.logo img').addClass('grayscale');
    });
    $('body').on('mouseover touchstart','.page-options .page-option',function(){
        $(this).find('.logo img').addClass('grayscale-50');
    });
    $('body').on('mouseout touchend','.page-options .page-option',function(){
        $(this).find('.logo img').removeClass('grayscale-50');
    });
     
});
