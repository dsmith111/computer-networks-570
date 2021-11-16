import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib import style

_AXES = []


def prepAnim(i):
    graph_data = open('latency.txt', 'r').read()
    lines = graph_data.split('\n')
    xs = []
    ys = []
    for line in lines:
        if len(line) > 1:
            x, y = line.split(',')
            xs.append(float(x))
            ys.append(float(y))
    _AXES[0].clear()
    _AXES[0].plot(xs, ys)


def Anim():
    fig = plt.figure()
    _AXES.append(fig.add_subplot(1, 1, 1))
    ani = animation.FuncAnimation(fig, prepAnim, interval=1000)
    plt.show()


if __name__ == "__main__":
    Anim()
