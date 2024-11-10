clear all;
clc;
close all;

% CSV import
%filename = "G:\My Drive\UNI\UniPD\Magistrale\Tesi\ckksPower.csv"; 
filename="C:\Users\betpa\Desktop\aes0311.xlsx";
%filename="C:\Users\betpa\Downloads\ckks (3).csv";

data = readmatrix(filename);

% Visualizzazione dati
disp(data);
x = data(:,2)';
y = data(:,3)';
points = 1000;

xi = linspace(min(x), max(x), points); 
tempo= max(x) - min(x);
delta_t = (tempo/points)* 1e-6;

% Cubic spline
yi = spline(x, y, xi);
% Graph
plot(x, y, 'o', 'MarkerSize', 8, 'DisplayName', 'Samples');  
hold on;
plot(xi, yi, '-', 'LineWidth', 2, 'DisplayName', 'Interpolation');  % Interpolation line
title('Cubic Spline');
xlabel('Time - ms');
ylabel('Power - mW');
legend;
grid on;

Energia = yi * delta_t; % Energia per interval
Energia_totale = sum(Energia); 

% Joule - mWh conversion
Energia_totale_mWh_aes = Energia_totale / 3.6;
disp(['Energia totale consumata: ', num2str(Energia_totale_mWh_aes), ' mWh']);


