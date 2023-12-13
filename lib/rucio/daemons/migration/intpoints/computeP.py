import numpy as np
from scipy.optimize import linprog

def AllAdj(c, A, b):
    """
    Find neighboring cells of a given cell `c`.

    Parameters:
    c (list): Sign vector representing the cell.
    A (numpy array): Coefficients of the hyperplanes.
    b (numpy array): Constants of the hyperplanes.

    Returns:
    list: Sign vectors of neighboring cells.
    """
    neighbors = []
    for i in range(len(c)):
        # Flip the sign of the i-th element in the sign vector
        new_c = c.copy()
        new_c[i] = -1 * new_c[i]

        # Check if the new sign vector corresponds to a valid cell
        if IntPt(new_c, A, b) is not None:
            neighbors.append(i)

    return neighbors

def IntPt(c, A, b, epsilon=1e-5):
    # Ensure A, b, and c are numpy arrays
    A = np.array(A)
    b = np.array(b)
    c = np.array(c)

    # Reshape c into a column vector
    c = c.reshape(-1, 1)

    # Adjust b by a small epsilon to ensure strict inequalities
    # If c is 1 (originally <=), we subtract epsilon to make it strictly <
    # If c is -1 (originally >=), we add epsilon to make it strictly >
    # Convert sign vector c into inequality constraints
    A_ineq = A * c
    b_ineq = b * c.ravel() - epsilon * np.abs(c.ravel())

    # Objective function is a zero vector since we just want a feasible point
    obj = np.zeros(A.shape[1])

    # Use linear programming to find a feasible point
    res = linprog(obj, A_ub=A_ineq, b_ub=b_ineq, method='highs')

    if res.success:
        # Return the feasible point if found
        return res.x
    else:
        # Return None if no feasible point is found
        return None


def CellEnum(c, A, b, visited, root_point):
    """
    Recursively enumerates all cells in the arrangement.

    Args:
    c: Sign vector representing the cell.
    A: Coefficient matrix of hyperplanes.
    b: Constant vector of hyperplanes.
    visited: Set to keep track of visited cells.
    """
    if tuple(c) in visited:
        return 
    visited.add(tuple(c))
    # print("Cell:", c)

    adj_cells = AllAdj(c, A, b)
    for h in adj_cells:
        new_c = c.copy()
        new_c[h] = -c[h]  # Flip the sign for the adjacent cell
        if tuple(new_c) not in visited and list(ParentSearch(new_c, A, b, root_point)) == list(c):
            CellEnum(new_c, A, b, visited, root_point)

def ParentSearch(c, A, b, r):
    """
    Identifies the unique parent cell of a given cell.

    Parameters:
    c: The cell for which the parent is to be identified, represented as a sign vector.
    A, b: Representations of the hyperplanes.
    r: A point (numpy array) inside the root cell.

    Returns:
    A sign vector representing the unique parent cell of c.
    """
    p = IntPt(c, A, b)  # Calculate the interior point of c
    h_k = findClosestHyperplaneIntersection(p, r, A, b)  # Index of the closest hyperplane
    if h_k == -1:
        return None  # No intersection found
    
    parent_c = c.copy()
    parent_c[h_k] = 1 if np.dot(A[h_k], p) > b[h_k] else -1
    return parent_c


def findClosestHyperplaneIntersection(p, r, A, b):
    """
    Find the hyperplane that intersects the line segment pr closest to p.

    Parameters:
    p: A point (numpy array) inside the cell.
    r: A point (numpy array) inside the root cell.
    A: Coefficient matrix of the hyperplanes.
    b: Intercept vector of the hyperplanes.

    Returns:
    Index of the hyperplane closest to point p.
    """
    min_distance = np.inf
    closest_hyperplane = -1

    for i in range(A.shape[0]):
        intersect_point = lineHyperplaneIntersection(p, r, A[i], b[i])
        if intersect_point is not None:
            distance = np.linalg.norm(intersect_point - p)
            if distance < min_distance:
                min_distance = distance
                closest_hyperplane = i

    return closest_hyperplane

def lineHyperplaneIntersection(p, r, Ai, bi):
    """
    Find the intersection point of a line and a hyperplane.

    Parameters:
    p, r: Points defining the line.
    Ai: Coefficient array for the hyperplane.
    bi: Intercept for the hyperplane.

    Returns:
    Intersection point as a numpy array or None if no intersection.
    """
    u = r - p
    denom = np.dot(Ai, u)
    if np.abs(denom) < 1e-10:  # Avoid division by zero; no intersection
        return None

    t = (bi - np.dot(Ai, p)) / denom

    if t < 0 or t > 1:  # Intersection point not within segment pr
        return None

    return p + t * u

def computePointsZeroB(A):
    A = np.array(A)
    b = np.zeros(A.shape[0])
    dimensions = np.shape(b)[0]
    sign_vector = np.ones(dimensions)
    visited = set()

    interior_point = IntPt(sign_vector, A, b)
    CellEnum(sign_vector, A, b, visited, interior_point)

    points = []

    for visit in visited: 
        points.append(IntPt(visit, A, b))

    return points

# if __name__ == '__main__':
#     visited = set()

#     A = np.array([
#         [-1, 0],  # -y <= -1
#         [1, 0],   # y <= 3
#         [0, -1],  # -x <= -1
#         [0, 1]    # x <= 4
#     ])

#     b = np.array([-1, 3, -1, 4])

#     print(computePoints(A, b))
